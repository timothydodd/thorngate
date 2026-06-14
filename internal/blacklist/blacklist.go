package blacklist

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry records why and when an IP was blacklisted. A zero Until means the ban
// is permanent (e.g. a honeypot hit); a non-zero Until is a temporary ban that
// expires at that time.
type Entry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Path      string    `json:"path,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Until     time.Time `json:"until,omitempty"`
}

func (e Entry) expired() bool {
	return !e.Until.IsZero() && time.Now().After(e.Until)
}

// Blacklist is a thread-safe set of blocked IPs with optional file persistence.
type Blacklist struct {
	mu      sync.RWMutex
	entries map[string]Entry
	file    string

	// whitelist holds parsed CIDRs / single IPs that are never blocked.
	whitelist []*net.IPNet
}

// New creates a Blacklist, loading any previously persisted entries from file.
// whitelist accepts plain IPs ("1.2.3.4") or CIDRs ("10.0.0.0/8").
func New(file string, whitelist []string) (*Blacklist, error) {
	b := &Blacklist{
		entries: make(map[string]Entry),
		file:    file,
	}

	for _, w := range whitelist {
		if !strings.Contains(w, "/") {
			// Treat a bare address as a single host.
			if strings.Contains(w, ":") {
				w += "/128" // IPv6
			} else {
				w += "/32" // IPv4
			}
		}
		_, ipnet, err := net.ParseCIDR(w)
		if err != nil {
			continue
		}
		b.whitelist = append(b.whitelist, ipnet)
	}

	if file != "" {
		if data, err := os.ReadFile(file); err == nil {
			var list []Entry
			if json.Unmarshal(data, &list) == nil {
				for _, e := range list {
					if e.expired() {
						continue // drop bans that lapsed while we were down
					}
					b.entries[e.IP] = e
				}
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return b, nil
}

// IsBlocked reports whether an IP is currently blacklisted. Expired temporary
// bans are removed lazily on lookup.
func (b *Blacklist) IsBlocked(ip string) bool {
	b.mu.RLock()
	e, ok := b.entries[ip]
	b.mu.RUnlock()
	if !ok {
		return false
	}
	if e.expired() {
		b.Remove(ip)
		return false
	}
	return true
}

// List returns a snapshot of all current entries.
func (b *Blacklist) List() []Entry {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.snapshotLocked()
}

// IsWhitelisted reports whether an IP should never be blacklisted.
func (b *Blacklist) IsWhitelisted(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range b.whitelist {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// Add permanently blacklists an IP and persists the set. No-op for whitelisted
// IPs. Returns true if the IP became (or was upgraded to) permanently blocked.
func (b *Blacklist) Add(ip, reason, path string) bool {
	return b.add(ip, reason, path, time.Time{})
}

// AddTemp blacklists an IP until now+dur. No-op for whitelisted IPs or IPs that
// are already permanently blocked. Returns true if a new temporary ban was set.
func (b *Blacklist) AddTemp(ip, reason string, dur time.Duration) bool {
	return b.add(ip, reason, "", time.Now().UTC().Add(dur))
}

func (b *Blacklist) add(ip, reason, path string, until time.Time) bool {
	if b.IsWhitelisted(ip) {
		return false
	}

	b.mu.Lock()
	existing, exists := b.entries[ip]
	if exists && !existing.expired() {
		permanentReq := until.IsZero()
		switch {
		case permanentReq && existing.Until.IsZero():
			b.mu.Unlock()
			return false // already permanent, nothing to do
		case permanentReq:
			// Upgrade an active temporary ban to permanent.
		case existing.Until.IsZero():
			b.mu.Unlock()
			return false // permanent ban outranks a temporary one
		default:
			// Refresh an existing temporary ban, extend if later.
			if until.Before(existing.Until) {
				until = existing.Until
			}
			b.entries[ip] = Entry{IP: ip, Reason: existing.Reason, Path: existing.Path,
				Timestamp: existing.Timestamp, Until: until}
			snapshot := b.snapshotLocked()
			b.mu.Unlock()
			b.persist(snapshot)
			return false // already blocked; don't re-log
		}
	}
	b.entries[ip] = Entry{IP: ip, Reason: reason, Path: path, Timestamp: time.Now().UTC(), Until: until}
	snapshot := b.snapshotLocked()
	b.mu.Unlock()

	b.persist(snapshot)
	return true
}

// Remove deletes an IP from the blacklist and persists the change. Returns true
// if the IP was present.
func (b *Blacklist) Remove(ip string) bool {
	b.mu.Lock()
	if _, ok := b.entries[ip]; !ok {
		b.mu.Unlock()
		return false
	}
	delete(b.entries, ip)
	snapshot := b.snapshotLocked()
	b.mu.Unlock()
	b.persist(snapshot)
	return true
}

// Count returns the number of blacklisted IPs.
func (b *Blacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries)
}

func (b *Blacklist) snapshotLocked() []Entry {
	list := make([]Entry, 0, len(b.entries))
	for _, e := range b.entries {
		list = append(list, e)
	}
	return list
}

func (b *Blacklist) persist(list []Entry) {
	if b.file == "" {
		return
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return
	}
	tmp := b.file + ".tmp"
	if os.WriteFile(tmp, data, 0o644) == nil {
		_ = os.Rename(tmp, b.file)
	}
}
