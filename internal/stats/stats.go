// Package stats keeps lightweight, in-memory traffic counters for the admin
// portal. Headline totals are lock-free atomics; a small per-minute ring buffer
// (guarded by a mutex) backs the traffic-over-time chart. Nothing touches disk
// on the request path — but the whole state (counters, series, recent feed) can
// optionally be dumped to a file periodically (Save) and pulled back in at
// startup (Load) so a restart doesn't wipe the dashboard.
package stats

import (
	"encoding/json"
	"fmt"
	"os"
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
	bytesSent atomic.Uint64 // response bytes written to clients by proxied requests

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
	Deny     string    `json:"deny,omitempty"`     // how a denied request ended: "tarpit" or "drop"; empty when a 403 was written (or the request was proxied)
	Upstream string    `json:"upstream,omitempty"` // resolved upstream URL; empty when never proxied
	Bytes    int64     `json:"bytes"`              // response bytes sent to the client; 0 when never proxied
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
	BytesSent uint64    `json:"bytes_sent"` // total response bytes sent by proxied requests
	Since     time.Time `json:"since"`
	Series    []Bucket  `json:"series"`
}

// RecentPage is one page of the recent-requests feed, newest first.
type RecentPage struct {
	Total    int            `json:"total"`     // events in the window across all pages
	Page     int            `json:"page"`      // 1-based page number, clamped to range
	PageSize int            `json:"page_size"` // events per page
	Events   []Event        `json:"events"`
	IPCounts map[string]int `json:"ip_counts"` // window-wide request count per IP appearing in Events
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

// Recent returns one page of the recent-requests feed, restricted to events no
// older than maxAge (<= 0 means no age limit). page is 1-based and clamped into
// range; pageSize <= 0 defaults to 50. IPCounts holds the window-wide request
// count for each IP that appears on the returned page, so the UI can flag
// chatty clients without shipping the whole window.
func (c *Collector) Recent(maxAge time.Duration, page, pageSize int) RecentPage {
	all := c.recentSnapshot()
	if maxAge > 0 {
		cutoff := time.Now().UTC().Add(-maxAge)
		// The feed is newest-first, so everything after the first stale event
		// is stale too.
		for i, e := range all {
			if e.Time.Before(cutoff) {
				all = all[:i]
				break
			}
		}
	}

	if pageSize <= 0 {
		pageSize = 50
	}
	pages := (len(all) + pageSize - 1) / pageSize
	if page < 1 {
		page = 1
	}
	if pages > 0 && page > pages {
		page = pages
	}
	start := (page - 1) * pageSize
	end := min(start+pageSize, len(all))
	events := all[start:end]

	counts := make(map[string]int, len(events))
	for _, e := range events {
		counts[e.IP] = 0
	}
	for _, e := range all {
		if _, ok := counts[e.IP]; ok {
			counts[e.IP]++
		}
	}

	return RecentPage{
		Total:    len(all),
		Page:     page,
		PageSize: pageSize,
		Events:   events,
		IPCounts: counts,
	}
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

// Bytes records response bytes sent to a client by a proxied request.
func (c *Collector) Bytes(n int64) {
	if n > 0 {
		c.bytesSent.Add(uint64(n))
	}
}

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
		BytesSent: c.bytesSent.Load(),
		Since:     c.since,
		Series:    series,
	}
}

// persisted is the on-disk representation of a Collector. Buckets carry their
// unix minute so stale ones can be discarded on load; Recent is oldest-first.
type persisted struct {
	Requests  uint64    `json:"requests"`
	Blocked   uint64    `json:"blocked"`
	Honeypots uint64    `json:"honeypots"`
	TempBans  uint64    `json:"temp_bans"`
	Status2xx uint64    `json:"status_2xx"`
	Status3xx uint64    `json:"status_3xx"`
	Status4xx uint64    `json:"status_4xx"`
	Status5xx uint64    `json:"status_5xx"`
	BytesSent uint64    `json:"bytes_sent"`
	Since     time.Time `json:"since"`
	Buckets   []Bucket  `json:"buckets"`
	Recent    []Event   `json:"recent"`
}

// Save atomically writes the collector's full state to file (temp file + fsync
// + rename, the same pattern the blacklist uses). Safe to call concurrently
// with request traffic.
func (c *Collector) Save(file string) error {
	if file == "" {
		return nil
	}
	p := persisted{
		Requests:  c.requests.Load(),
		Blocked:   c.blocked.Load(),
		Honeypots: c.honeypots.Load(),
		TempBans:  c.tempBans.Load(),
		Status2xx: c.s2xx.Load(),
		Status3xx: c.s3xx.Load(),
		Status4xx: c.s4xx.Load(),
		Status5xx: c.s5xx.Load(),
		BytesSent: c.bytesSent.Load(),
		Since:     c.since,
	}

	c.mu.Lock()
	for _, b := range c.buckets {
		if b.min != 0 {
			p.Buckets = append(p.Buckets, Bucket{Minute: b.min, Requests: b.reqs, Blocked: b.blk})
		}
	}
	c.mu.Unlock()

	newestFirst := c.recentSnapshot()
	p.Recent = make([]Event, 0, len(newestFirst))
	for i := len(newestFirst) - 1; i >= 0; i-- {
		p.Recent = append(p.Recent, newestFirst[i])
	}

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	tmp := file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, file)
}

// Load restores state previously written by Save. A missing file is not an
// error (fresh install). Series buckets that have aged out of the window and
// recent events beyond the feed's capacity are dropped. Call it before the
// proxy starts serving traffic.
func (c *Collector) Load(file string) error {
	if file == "" {
		return nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var p persisted
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse: %w", err)
	}

	c.requests.Store(p.Requests)
	c.blocked.Store(p.Blocked)
	c.honeypots.Store(p.Honeypots)
	c.tempBans.Store(p.TempBans)
	c.s2xx.Store(p.Status2xx)
	c.s3xx.Store(p.Status3xx)
	c.s4xx.Store(p.Status4xx)
	c.s5xx.Store(p.Status5xx)
	c.bytesSent.Store(p.BytesSent)
	if !p.Since.IsZero() {
		c.since = p.Since
	}

	cur := time.Now().UTC().Unix() / 60
	n := int64(len(c.buckets))
	c.mu.Lock()
	for _, b := range p.Buckets {
		if b.Minute > cur || b.Minute <= cur-n {
			continue // outside the live window
		}
		c.buckets[int(b.Minute%n)] = bucket{min: b.Minute, reqs: b.Requests, blk: b.Blocked}
	}
	c.mu.Unlock()

	// Refill the recent feed oldest-first so the ring's write position ends up
	// exactly where it would be had the events been observed live. If the saved
	// feed exceeds the (possibly reconfigured) capacity, keep the newest.
	recent := p.Recent
	if capacity := len(c.recent); capacity > 0 && len(recent) > capacity {
		recent = recent[len(recent)-capacity:]
	}
	for _, e := range recent {
		c.Observe(e)
	}
	return nil
}
