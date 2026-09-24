package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"thorngate/internal/blacklist"
	"thorngate/internal/stats"
)

// maxPageSize caps page_size so a single request can't dump the whole history.
const maxPageSize = 200

// defaultRange is how far back traffic views look when no range is given.
const defaultRange = 24 * time.Hour

// history picks what answers traffic questions: the on-disk archive when
// configured (long retention), else the in-memory feed. Nil if stats are off.
func (s *server) history() stats.History {
	if s.Archive != nil {
		return s.Archive
	}
	if s.Stats != nil {
		return s.Stats
	}
	return nil
}

// parseSpan parses a look-back like "24h", "90m" or "7d" (Go durations plus a
// "d" day suffix).
func parseSpan(v string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("invalid range %q", v)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid range %q", v)
	}
	return d, nil
}

// since reads the range query parameter (default def) as a start time. On a
// bad value it writes a 400 and returns ok=false.
func since(w http.ResponseWriter, r *http.Request, def time.Duration) (time.Time, bool) {
	span := def
	if v := r.URL.Query().Get("range"); v != "" {
		d, err := parseSpan(v)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return time.Time{}, false
		}
		span = d
	}
	return time.Now().UTC().Add(-span), true
}

// archiveInfo describes the on-disk history for the dashboard.
type archiveInfo struct {
	Enabled       bool   `json:"enabled"`
	RetentionDays int    `json:"retention_days,omitempty"`
	Segments      int    `json:"segments,omitempty"`
	Bytes         int64  `json:"bytes,omitempty"`
	Dropped       uint64 `json:"dropped,omitempty"`
}

func (s *server) archiveInfo() archiveInfo {
	if s.Archive == nil {
		return archiveInfo{}
	}
	segs, bytes := s.Archive.Usage()
	return archiveInfo{
		Enabled:       true,
		RetentionDays: int(s.Archive.Retention() / (24 * time.Hour)),
		Segments:      segs,
		Bytes:         bytes,
		Dropped:       s.Archive.Dropped(),
	}
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.Stats == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "stats": s.Stats.Snapshot(), "archive": s.archiveInfo()})
}

// handleRequests serves one page of the request history, filtered by the
// ip (IP or CIDR), outcome, status (2xx..5xx|none), q (text) and range query
// parameters. IPs on the page that are currently banned are flagged.
func (s *server) handleRequests(w http.ResponseWriter, r *http.Request) {
	h := s.history()
	if h == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	from, ok := since(w, r, defaultRange)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := stats.Filter{
		IP:      q.Get("ip"),
		Outcome: q.Get("outcome"),
		Status:  q.Get("status"),
		Text:    q.Get("q"),
		Since:   from,
	}
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	size = min(size, maxPageSize)

	res, err := h.Query(f, page, size)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	res.Banned = s.bannedAmong(res.Events)
	writeJSON(w, http.StatusOK, struct {
		Enabled bool `json:"enabled"`
		Archive bool `json:"archive"`
		stats.RecentPage
	}{true, s.Archive != nil, res})
}

// bannedAmong flags which IPs among events are currently blocked.
func (s *server) bannedAmong(events []stats.Event) map[string]bool {
	out := map[string]bool{}
	for _, e := range events {
		if _, seen := out[e.IP]; !seen {
			out[e.IP] = s.Blacklist.IsBlocked(e.IP)
		}
	}
	return out
}

func (s *server) handleTop(w http.ResponseWriter, r *http.Request) {
	h := s.history()
	if h == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	from, ok := since(w, r, defaultRange)
	if !ok {
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 || n > 50 {
		n = 10
	}
	top, err := h.Top(from, n)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	banned := map[string]bool{}
	for _, c := range top.IPs {
		banned[c.Key] = s.Blacklist.IsBlocked(c.Key)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled": true, "ips": top.IPs, "paths": top.Paths, "banned": banned})
}

func (s *server) handleHourly(w http.ResponseWriter, r *http.Request) {
	h := s.history()
	if h == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	from, ok := since(w, r, 7*24*time.Hour)
	if !ok {
		return
	}
	series, err := h.Hourly(from)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "series": series})
}

// handleIP profiles one client: its ban (including a covering range), whether
// it's whitelisted, and a summary of its traffic over the range.
func (s *server) handleIP(w http.ResponseWriter, r *http.Request) {
	ip := blacklist.NormalizeKey(r.PathValue("ip"))
	if !validBanKey(ip) || strings.Contains(ip, "/") {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
		return
	}
	def := defaultRange
	if s.Archive != nil {
		def = s.Archive.Retention()
	}
	from, ok := since(w, r, def)
	if !ok {
		return
	}
	out := map[string]any{
		"ip":          ip,
		"whitelisted": s.Blacklist.IsWhitelisted(ip),
		"ban":         nil,
	}
	if e, banned := s.Blacklist.Lookup(ip); banned {
		out["ban"] = e
	}
	if h := s.history(); h != nil {
		sum, err := h.IPSummary(ip, from)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		out["summary"] = sum
	}
	writeJSON(w, http.StatusOK, out)
}
