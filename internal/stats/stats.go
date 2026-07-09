// Package stats keeps lightweight, in-memory traffic counters for the admin
// portal. Headline totals are lock-free atomics; a small per-minute ring buffer
// (guarded by a mutex) backs the traffic-over-time chart. Everything is
// memory-only and resets on restart — nothing is persisted, by design.
package stats

import (
	"sync"
	"sync/atomic"
	"time"
)

// Collector accumulates request counters and a rolling per-minute time series.
// The zero value is not usable; call New.
type Collector struct {
	requests  atomic.Uint64
	blocked   atomic.Uint64 // requests rejected by an existing blacklist entry
	honeypots atomic.Uint64 // honeypot hits that produced a ban
	tempBans  atomic.Uint64 // temp-bans applied for too many bad responses
	s2xx      atomic.Uint64
	s3xx      atomic.Uint64
	s4xx      atomic.Uint64
	s5xx      atomic.Uint64

	since time.Time

	mu      sync.Mutex
	buckets []bucket // ring indexed by (unix-minute % len)

	recentMu  sync.Mutex
	recent    []Event // ring buffer of the most recent observed requests
	recentPos int     // index of the next write
	recentLen int     // number of valid entries (grows to len(recent))
}

// Event is one observed request kept in the recent-requests feed.
type Event struct {
	Time     time.Time `json:"time"`
	IP       string    `json:"ip"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	Path     string    `json:"path"`
	Query    string    `json:"query,omitempty"`
	Status   int       `json:"status"`
	Outcome  string    `json:"outcome"`            // "proxied", "blocked", or "honeypot"
	Upstream string    `json:"upstream,omitempty"` // resolved upstream URL; empty when never proxied
}

// bucket holds one minute of the time series. min is the unix-minute the slot
// currently represents, so a stale slot can be detected and reset on reuse.
type bucket struct {
	min  int64
	reqs uint64
	blk  uint64
}

// Snapshot is a point-in-time copy of the counters, safe to serialize to JSON.
type Snapshot struct {
	Requests  uint64    `json:"requests"`
	Blocked   uint64    `json:"blocked"`
	Honeypots uint64    `json:"honeypots"`
	TempBans  uint64    `json:"temp_bans"`
	Status2xx uint64    `json:"status_2xx"`
	Status3xx uint64    `json:"status_3xx"`
	Status4xx uint64    `json:"status_4xx"`
	Status5xx uint64    `json:"status_5xx"`
	Since     time.Time `json:"since"`
	Series    []Bucket  `json:"series"`
	Recent    []Event   `json:"recent"` // most recent requests, newest first
}

// Bucket is one minute of the traffic-over-time series.
type Bucket struct {
	Minute   int64  `json:"t"` // unix minute (seconds = t*60)
	Requests uint64 `json:"requests"`
	Blocked  uint64 `json:"blocked"`
}

// New returns a Collector whose time series covers the last windowMinutes
// minutes and whose recent-requests feed keeps the last recent events.
// windowMinutes <= 0 defaults to 60; recent < 0 is clamped to 0 (feed off).
func New(windowMinutes, recent int) *Collector {
	if windowMinutes <= 0 {
		windowMinutes = 60
	}
	if recent < 0 {
		recent = 0
	}
	return &Collector{
		since:   time.Now().UTC(),
		buckets: make([]bucket, windowMinutes),
		recent:  make([]Event, recent),
	}
}

// Observe records a request in the recent-requests feed. It is a no-op when the
// feed is disabled (capacity 0).
func (c *Collector) Observe(e Event) {
	if len(c.recent) == 0 {
		return
	}
	c.recentMu.Lock()
	c.recent[c.recentPos] = e
	c.recentPos = (c.recentPos + 1) % len(c.recent)
	if c.recentLen < len(c.recent) {
		c.recentLen++
	}
	c.recentMu.Unlock()
}

// recentSnapshot returns the recent-requests feed newest-first.
func (c *Collector) recentSnapshot() []Event {
	c.recentMu.Lock()
	defer c.recentMu.Unlock()
	n := len(c.recent)
	out := make([]Event, 0, c.recentLen)
	for i := 1; i <= c.recentLen; i++ {
		out = append(out, c.recent[((c.recentPos-i)%n+n)%n])
	}
	return out
}

// Request records that a request was received. blocked reports whether it was
// rejected outright by an existing blacklist entry. It feeds both the headline
// totals and the per-minute series.
func (c *Collector) Request(blocked bool) {
	c.requests.Add(1)
	if blocked {
		c.blocked.Add(1)
	}
	c.tick(time.Now().UTC(), blocked)
}

// Honeypot records a honeypot hit that produced a fresh ban.
func (c *Collector) Honeypot() { c.honeypots.Add(1) }

// TempBan records a temp-ban applied for too many bad responses.
func (c *Collector) TempBan() { c.tempBans.Add(1) }

// Status records the final status code of a proxied response, bucketed by class.
func (c *Collector) Status(code int) {
	switch {
	case code >= 200 && code < 300:
		c.s2xx.Add(1)
	case code >= 300 && code < 400:
		c.s3xx.Add(1)
	case code >= 400 && code < 500:
		c.s4xx.Add(1)
	case code >= 500:
		c.s5xx.Add(1)
	}
}

// tick bumps the current minute's bucket, rotating the ring as time advances.
func (c *Collector) tick(now time.Time, blocked bool) {
	cur := now.Unix() / 60
	c.mu.Lock()
	b := &c.buckets[int(cur%int64(len(c.buckets)))]
	if b.min != cur {
		// Slot belongs to an older minute; reclaim it for the current one.
		b.min, b.reqs, b.blk = cur, 0, 0
	}
	b.reqs++
	if blocked {
		b.blk++
	}
	c.mu.Unlock()
}

// Snapshot returns a copy of all counters and a continuous, chronological time
// series (one entry per minute in the window; minutes with no traffic are zero).
func (c *Collector) Snapshot() Snapshot {
	cur := time.Now().UTC().Unix() / 60
	n := len(c.buckets)

	c.mu.Lock()
	cp := make([]bucket, n)
	copy(cp, c.buckets)
	c.mu.Unlock()

	series := make([]Bucket, 0, n)
	for m := cur - int64(n) + 1; m <= cur; m++ {
		b := cp[int(m%int64(n))]
		out := Bucket{Minute: m}
		if b.min == m {
			out.Requests, out.Blocked = b.reqs, b.blk
		}
		series = append(series, out)
	}

	return Snapshot{
		Requests:  c.requests.Load(),
		Blocked:   c.blocked.Load(),
		Honeypots: c.honeypots.Load(),
		TempBans:  c.tempBans.Load(),
		Status2xx: c.s2xx.Load(),
		Status3xx: c.s3xx.Load(),
		Status4xx: c.s4xx.Load(),
		Status5xx: c.s5xx.Load(),
		Since:     c.since,
		Series:    series,
		Recent:    c.recentSnapshot(),
	}
}
