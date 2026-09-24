package stats

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// History answers the admin portal's questions about past requests. The
// Collector implements it over its in-memory feed; internal/archive implements
// it over on-disk hourly segments for much longer retention. Every method
// returns events newest first.
type History interface {
	// Query returns one page of the events matching f.
	Query(f Filter, page, pageSize int) (RecentPage, error)
	// Top returns the busiest IPs and paths since the given time.
	Top(since time.Time, n int) (Top, error)
	// IPSummary profiles one client's requests since the given time.
	IPSummary(ip string, since time.Time) (IPSummary, error)
	// Hourly returns one bucket per hour since the given time (oldest first).
	Hourly(since time.Time) ([]Bucket, error)
}

// Filter selects events from the request history. Zero fields match
// everything. Call Compile before Match.
type Filter struct {
	IP      string    // single IP or CIDR range
	Outcome string    // "proxied", "blocked" or "honeypot"
	Status  string    // "2xx".."5xx", or "none" for denied requests that got no response
	Text    string    // case-insensitive substring of host, path, query or user agent
	Since   time.Time // inclusive; zero = no lower bound
	Until   time.Time // exclusive; zero = no upper bound

	ip       string
	net      *net.IPNet
	text     string
	compiled bool
}

// Compile validates the filter and prepares it for Match.
func (f *Filter) Compile() error {
	f.ip, f.net = "", nil
	if s := strings.TrimSpace(f.IP); s != "" {
		if strings.Contains(s, "/") {
			_, n, err := net.ParseCIDR(s)
			if err != nil {
				return fmt.Errorf("invalid IP or CIDR %q", s)
			}
			f.net = n
		} else if p := net.ParseIP(s); p != nil {
			f.ip = p.String()
		} else {
			return fmt.Errorf("invalid IP or CIDR %q", s)
		}
	}
	switch f.Outcome {
	case "", "proxied", "blocked", "honeypot":
	default:
		return fmt.Errorf("invalid outcome %q", f.Outcome)
	}
	switch f.Status {
	case "", "2xx", "3xx", "4xx", "5xx", "none":
	default:
		return fmt.Errorf("invalid status class %q", f.Status)
	}
	f.text = strings.ToLower(strings.TrimSpace(f.Text))
	f.compiled = true
	return nil
}

// ExactIP returns the single address the filter selects, or "" if it doesn't
// select exactly one.
func (f *Filter) ExactIP() string { return f.ip }

// Indexed reports whether only the time range and (at most) an exact IP are
// set — questions a per-hour index of IP counts can answer without reading
// events.
func (f *Filter) Indexed() bool {
	return f.net == nil && f.Outcome == "" && f.Status == "" && f.text == ""
}

// InRange reports whether t falls within the filter's time range.
func (f *Filter) InRange(t time.Time) bool {
	return (f.Since.IsZero() || !t.Before(f.Since)) && (f.Until.IsZero() || t.Before(f.Until))
}

// Match reports whether e passes the filter.
func (f *Filter) Match(e *Event) bool {
	if !f.compiled {
		panic("stats: Filter.Match before Compile")
	}
	if !f.InRange(e.Time) {
		return false
	}
	if f.ip != "" && e.IP != f.ip {
		return false
	}
	if f.net != nil {
		p := net.ParseIP(e.IP)
		if p == nil || !f.net.Contains(p) {
			return false
		}
	}
	if f.Outcome != "" && e.Outcome != f.Outcome {
		return false
	}
	if f.Status != "" && StatusClass(e.Status) != f.Status {
		return false
	}
	if f.text != "" && !containsFold(f.text, e.Host, e.Path, e.Query, e.UA) {
		return false
	}
	return true
}

func containsFold(needle string, hay ...string) bool {
	for _, h := range hay {
		if strings.Contains(strings.ToLower(h), needle) {
			return true
		}
	}
	return false
}

// StatusClass buckets a status code: "2xx".."5xx", or "none" when no response
// was written (a dropped or tarpitted request).
func StatusClass(code int) string {
	if code <= 0 {
		return "none"
	}
	return fmt.Sprintf("%dxx", code/100)
}

// Counted is a key with an occurrence count.
type Counted struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// Top holds the busiest IPs and paths over a time range.
type Top struct {
	IPs   []Counted `json:"ips"`
	Paths []Counted `json:"paths"`
}

// TopN returns the n highest counts, ties broken by key for stable output.
func TopN(m map[string]int, n int) []Counted {
	out := make([]Counted, 0, len(m))
	for k, v := range m {
		out = append(out, Counted{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// IPSummary profiles one client's requests over a time range.
type IPSummary struct {
	IP        string         `json:"ip"`
	Requests  int            `json:"requests"`
	Outcomes  map[string]int `json:"outcomes"`
	Statuses  map[string]int `json:"statuses"` // by StatusClass
	Paths     []Counted      `json:"paths"`    // top paths
	Hosts     []Counted      `json:"hosts"`    // top hosts
	FirstSeen *time.Time     `json:"first_seen,omitempty"`
	LastSeen  *time.Time     `json:"last_seen,omitempty"`
	Country   string         `json:"country,omitempty"` // most recent non-empty value
	UA        string         `json:"ua,omitempty"`      // most recent non-empty value
}

// Summarizer accumulates an IPSummary from events fed newest first.
type Summarizer struct {
	s            IPSummary
	paths, hosts map[string]int
}

// NewSummarizer starts a summary for ip.
func NewSummarizer(ip string) *Summarizer {
	return &Summarizer{
		s:     IPSummary{IP: ip, Outcomes: map[string]int{}, Statuses: map[string]int{}},
		paths: map[string]int{},
		hosts: map[string]int{},
	}
}

// Add counts one event. Events must arrive newest first.
func (z *Summarizer) Add(e *Event) {
	s := &z.s
	if s.Requests == 0 {
		t := e.Time
		s.LastSeen = &t
	}
	// Newest non-empty values: one request without the header shouldn't
	// blank what the others reported.
	if s.Country == "" {
		s.Country = e.Country
	}
	if s.UA == "" {
		s.UA = e.UA
	}
	t := e.Time
	s.FirstSeen = &t
	s.Requests++
	s.Outcomes[e.Outcome]++
	s.Statuses[StatusClass(e.Status)]++
	z.paths[e.Path]++
	z.hosts[e.Host]++
}

// Result returns the finished summary.
func (z *Summarizer) Result() IPSummary {
	s := z.s
	s.Paths = TopN(z.paths, 10)
	s.Hosts = TopN(z.hosts, 5)
	return s
}

// PageBounds clamps a 1-based page against total matches and returns the
// half-open [start, end) range of match indices it covers. pageSize <= 0
// defaults to 50.
func PageBounds(total, page, pageSize int) (p, size, start, end int) {
	if pageSize <= 0 {
		pageSize = 50
	}
	pages := (total + pageSize - 1) / pageSize
	if page < 1 {
		page = 1
	}
	if pages > 0 && page > pages {
		page = pages
	}
	start = (page - 1) * pageSize
	end = min(start+pageSize, total)
	return page, pageSize, start, end
}

// HourlyFrame returns empty buckets for every hour from since's hour through
// the current hour, keyed by unix minute of the hour start, so a series is
// continuous even through hours with no traffic.
func HourlyFrame(since time.Time) ([]Bucket, map[int64]int) {
	start := since.UTC().Truncate(time.Hour)
	now := time.Now().UTC().Truncate(time.Hour)
	var out []Bucket
	idx := map[int64]int{}
	for h := start; !h.After(now); h = h.Add(time.Hour) {
		m := h.Unix() / 60
		idx[m] = len(out)
		out = append(out, Bucket{Minute: m})
	}
	return out, idx
}
