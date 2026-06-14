// Package history keeps a short, memory-bounded record of the most recent
// requests each client IP made while it was still allowed through. When that IP
// is later blacklisted, the proxy dumps this history to the log so emerging
// attack patterns (the recon that precedes a honeypot hit) can be researched.
package history

import (
	"sync"
	"time"
)

// Record is a single proxied request remembered for forensic context.
type Record struct {
	Time   time.Time
	Method string
	Host   string
	Path   string
	Query  string
	UA     string
	Status int
}

type entry struct {
	recs []Record
	seen time.Time
}

// Tracker keeps the last N proxied requests per client IP, bounded in both
// per-IP depth and total tracked IPs so a flood of distinct sources can't
// exhaust memory.
type Tracker struct {
	mu     sync.Mutex
	ips    map[string]*entry
	depth  int
	maxIPs int
	ttl    time.Duration
}

// New returns a Tracker that remembers up to depth requests per IP, tracks at
// most maxIPs distinct IPs at once, and drops IPs idle longer than ttl on Sweep.
func New(depth, maxIPs int, ttl time.Duration) *Tracker {
	return &Tracker{
		ips:    make(map[string]*entry),
		depth:  depth,
		maxIPs: maxIPs,
		ttl:    ttl,
	}
}

// Record appends a request to the IP's ring buffer, dropping the oldest once the
// buffer is full. When a brand-new IP would exceed maxIPs, the least-recently
// active IP is evicted first.
func (t *Tracker) Record(ip string, r Record) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e := t.ips[ip]
	if e == nil {
		if len(t.ips) >= t.maxIPs {
			t.evictOldestLocked()
		}
		e = &entry{}
		t.ips[ip] = e
	}
	e.seen = r.Time
	e.recs = append(e.recs, r)
	if len(e.recs) > t.depth {
		// Keep only the most recent depth records.
		e.recs = append(e.recs[:0], e.recs[len(e.recs)-t.depth:]...)
	}
}

// History returns a copy of the IP's remembered requests, oldest first.
func (t *Tracker) History(ip string) []Record {
	t.mu.Lock()
	defer t.mu.Unlock()
	e := t.ips[ip]
	if e == nil {
		return nil
	}
	out := make([]Record, len(e.recs))
	copy(out, e.recs)
	return out
}

// Forget drops an IP's history. Called once it has been logged on blacklist so
// the memory is reclaimed immediately rather than waiting for a Sweep.
func (t *Tracker) Forget(ip string) {
	t.mu.Lock()
	delete(t.ips, ip)
	t.mu.Unlock()
}

// Sweep drops IPs that have been idle longer than the TTL. Call periodically to
// keep memory bounded for IPs that are never blacklisted.
func (t *Tracker) Sweep() {
	cutoff := time.Now().Add(-t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	for ip, e := range t.ips {
		if e.seen.Before(cutoff) {
			delete(t.ips, ip)
		}
	}
}

// evictOldestLocked removes the least-recently active IP. Caller holds the lock.
func (t *Tracker) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	first := true
	for ip, e := range t.ips {
		if first || e.seen.Before(oldest) {
			oldest, oldestIP, first = e.seen, ip, false
		}
	}
	if oldestIP != "" {
		delete(t.ips, oldestIP)
	}
}
