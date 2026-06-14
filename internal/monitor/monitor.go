// Package monitor tracks per-IP "strikes" (bad responses) within a sliding
// time window to decide when an IP should be temporarily banned.
package monitor

import (
	"sync"
	"time"
)

// Monitor counts strikes per IP over a sliding window.
type Monitor struct {
	mu     sync.Mutex
	hits   map[string][]time.Time
	max    int
	window time.Duration
}

// New returns a Monitor that triggers once an IP reaches max strikes in window.
func New(max int, window time.Duration) *Monitor {
	return &Monitor{
		hits:   make(map[string][]time.Time),
		max:    max,
		window: window,
	}
}

// Strike records a strike for ip and reports whether it has reached the
// threshold within the window. When it triggers, the IP's counter is reset so a
// single burst yields a single ban.
func (m *Monitor) Strike(ip string) bool {
	now := time.Now()
	cutoff := now.Add(-m.window)

	m.mu.Lock()
	defer m.mu.Unlock()

	times := m.hits[ip]
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)

	if len(kept) >= m.max {
		delete(m.hits, ip)
		return true
	}
	m.hits[ip] = kept
	return false
}

// Sweep drops IPs with no strikes left inside the window. Call periodically to
// keep memory bounded.
func (m *Monitor) Sweep() {
	cutoff := time.Now().Add(-m.window)
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, times := range m.hits {
		fresh := false
		for _, t := range times {
			if t.After(cutoff) {
				fresh = true
				break
			}
		}
		if !fresh {
			delete(m.hits, ip)
		}
	}
}
