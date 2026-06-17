package blacklist

import (
	"encoding/json"
	"log"
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

// cidrEntry is a blacklisted CIDR range: the parsed network plus the ban
// metadata. CIDR bans are kept in a slice (walked linearly) rather than the
// exact-IP map, since they match by containment.
type cidrEntry struct {
	net   *net.IPNet
	entry Entry
}

// Blacklist is a thread-safe set of blocked IPs with optional file persistence.
// Exact IPs are stored in a hash map for O(1) lookup; CIDR ranges are stored
// separately and matched by containment.
type Blacklist struct {
	mu      sync.RWMutex
	entries map[string]Entry
	cidrs   []cidrEntry
	file    string

	// whitelist holds parsed CIDRs / single IPs that are never blocked.
	whitelist []*net.IPNet
}

// isCIDR reports whether a ban key denotes a CIDR range rather than a single IP.
func isCIDR(key string) bool { return strings.Contains(key, "/") }

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
					if _, ipnet, err := net.ParseCIDR(e.IP); err == nil {
						b.cidrs = append(b.cidrs, cidrEntry{net: ipnet, entry: e})
					} else {
						b.entries[e.IP] = e
					}
				}
			}
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return b, nil
}

// IsBlocked reports whether an IP is currently blacklisted, either by an exact
// match or because it falls within a blacklisted CIDR range. Expired exact bans
// are removed lazily on lookup; a whitelisted IP is never reported as blocked,
// even if it sits inside a banned range.
func (b *Blacklist) IsBlocked(ip string) bool {
	b.mu.RLock()
	e, ok := b.entries[ip]
	b.mu.RUnlock()
	if ok {
		if e.expired() {
			b.Remove(ip)
			return false
		}
		return true
	}

	b.mu.RLock()
	hasCIDRs := len(b.cidrs) > 0
	b.mu.RUnlock()
	if !hasCIDRs {
		return false
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || b.IsWhitelisted(ip) {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, c := range b.cidrs {
		if c.net.Contains(parsed) && !c.entry.expired() {
			return true
		}
	}
	return false
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

// Add permanently blacklists an IP or CIDR range (e.g. "1.2.3.4" or
// "1.2.3.0/24") and persists the set. No-op for whitelisted IPs. Returns true if
// the entry became (or was upgraded to) permanently blocked.
func (b *Blacklist) Add(ip, reason, path string) bool {
	return b.add(ip, reason, path, time.Time{})
}

// AddTemp blacklists an IP until now+dur. No-op for whitelisted IPs or IPs that
// are already permanently blocked. Returns true if a new temporary ban was set.
func (b *Blacklist) AddTemp(ip, reason string, dur time.Duration) bool {
	return b.add(ip, reason, "", time.Now().UTC().Add(dur))
}

func (b *Blacklist) add(ip, reason, path string, until time.Time) bool {
	if isCIDR(ip) {
		return b.addCIDR(ip, reason, path, until)
	}
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

// addCIDR is the CIDR-range counterpart of add. It mirrors add's temp/permanent
// reconciliation but matches existing entries by normalized network rather than
// map key. An unparseable CIDR is a no-op returning false.
func (b *Blacklist) addCIDR(cidr, reason, path string, until time.Time) bool {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	key := ipnet.String() // normalized, e.g. "1.2.3.4/24" -> "1.2.3.0/24"

	b.mu.Lock()
	for i := range b.cidrs {
		if b.cidrs[i].net.String() != key {
			continue
		}
		existing := b.cidrs[i].entry
		if !existing.expired() {
			permanentReq := until.IsZero()
			switch {
			case permanentReq && existing.Until.IsZero():
				b.mu.Unlock()
				return false // already permanent, nothing to do
			case permanentReq:
				// Upgrade an active temporary ban to permanent (fall through).
			case existing.Until.IsZero():
				b.mu.Unlock()
				return false // permanent ban outranks a temporary one
			default:
				// Refresh an existing temporary ban, extend if later.
				if until.Before(existing.Until) {
					until = existing.Until
				}
				b.cidrs[i].entry = Entry{IP: existing.IP, Reason: existing.Reason, Path: existing.Path,
					Timestamp: existing.Timestamp, Until: until}
				snapshot := b.snapshotLocked()
				b.mu.Unlock()
				b.persist(snapshot)
				return false // already blocked; don't re-log
			}
		}
		b.cidrs[i].entry = Entry{IP: cidr, Reason: reason, Path: path, Timestamp: time.Now().UTC(), Until: until}
		snapshot := b.snapshotLocked()
		b.mu.Unlock()
		b.persist(snapshot)
		return true
	}
	b.cidrs = append(b.cidrs, cidrEntry{net: ipnet,
		entry: Entry{IP: cidr, Reason: reason, Path: path, Timestamp: time.Now().UTC(), Until: until}})
	snapshot := b.snapshotLocked()
	b.mu.Unlock()
	b.persist(snapshot)
	return true
}

// Remove deletes an IP or CIDR range from the blacklist and persists the change.
// A CIDR may be passed either as originally stored or in normalized form.
// Returns true if an entry was present.
func (b *Blacklist) Remove(ip string) bool {
	b.mu.Lock()
	if _, ok := b.entries[ip]; ok {
		delete(b.entries, ip)
		snapshot := b.snapshotLocked()
		b.mu.Unlock()
		b.persist(snapshot)
		return true
	}
	for i := range b.cidrs {
		if b.cidrs[i].entry.IP == ip || b.cidrs[i].net.String() == ip {
			b.cidrs = append(b.cidrs[:i], b.cidrs[i+1:]...)
			snapshot := b.snapshotLocked()
			b.mu.Unlock()
			b.persist(snapshot)
			return true
		}
	}
	b.mu.Unlock()
	return false
}

// Count returns the number of blacklisted entries (exact IPs and CIDR ranges).
func (b *Blacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.entries) + len(b.cidrs)
}

func (b *Blacklist) snapshotLocked() []Entry {
	list := make([]Entry, 0, len(b.entries)+len(b.cidrs))
	for _, e := range b.entries {
		list = append(list, e)
	}
	for _, c := range b.cidrs {
		list = append(list, c.entry)
	}
	return list
}

// persist atomically writes the blacklist to disk: write to a temp file, fsync
// it so the data is durable, then rename over the target. Unlike a fire-and-
// forget write, every failure is logged so a broken persistence path (read-only
// mount, full disk) is visible rather than silently dropping bans on restart.
func (b *Blacklist) persist(list []Entry) {
	if b.file == "" {
		return
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		log.Printf("blacklist: marshal failed: %v", err)
		return
	}
	tmp := b.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		log.Printf("blacklist: open %s failed: %v", tmp, err)
		return
	}
	if _, err := f.Write(data); err != nil {
		log.Printf("blacklist: write %s failed: %v", tmp, err)
		_ = f.Close()
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("blacklist: fsync %s failed: %v", tmp, err)
		_ = f.Close()
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("blacklist: close %s failed: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, b.file); err != nil {
		log.Printf("blacklist: rename %s -> %s failed: %v", tmp, b.file, err)
	}
}
