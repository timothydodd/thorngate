package admin

import (
	"fmt"
	"io"
	"net/http"
)

// handleMetrics serves Prometheus text-format metrics. It is unauthenticated
// (scrapers rarely carry credentials) and exposes only counters; the admin
// port is cluster-internal. Disable with admin.disable_metrics.
func (s *server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	m := metricWriter{w}

	if s.Stats != nil {
		snap := s.Stats.Snapshot()
		m.counter("thorngate_requests_total", "Requests received.", snap.Requests)
		m.counter("thorngate_blocked_total", "Requests rejected by an existing blacklist entry.", snap.Blocked)
		m.counter("thorngate_honeypot_bans_total", "Bans from honeypot hits.", snap.Honeypots)
		m.counter("thorngate_temp_bans_total", "Temporary bans for too many bad responses.", snap.TempBans)
		m.counter("thorngate_escalated_bans_total", "Temporary bans escalated to permanent.", snap.Escalated)
		m.header("thorngate_responses_total", "Proxied responses by status class.", "counter")
		for _, c := range []struct {
			class string
			n     uint64
		}{{"2xx", snap.Status2xx}, {"3xx", snap.Status3xx}, {"4xx", snap.Status4xx}, {"5xx", snap.Status5xx}} {
			fmt.Fprintf(w, "thorngate_responses_total{class=%q} %d\n", c.class, c.n)
		}
		m.counter("thorngate_response_bytes_total", "Response body bytes sent to clients by proxied requests.", snap.BytesSent)
	}
	m.gauge("thorngate_blacklist_entries", "Current blacklist entries (IPs and ranges).", int64(s.Blacklist.Count()))
	if s.Tarpitting != nil {
		m.gauge("thorngate_tarpit_connections", "Connections currently held by the tarpit.", s.Tarpitting())
	}
	if s.Archive != nil {
		_, bytes := s.Archive.Usage()
		m.counter("thorngate_archive_dropped_total", "Requests not archived because the writer fell behind.", s.Archive.Dropped())
		m.gauge("thorngate_archive_bytes", "Disk used by the request archive.", bytes)
	}
}

type metricWriter struct{ w io.Writer }

func (m metricWriter) header(name, help, typ string) {
	fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (m metricWriter) counter(name, help string, v uint64) {
	m.header(name, help, "counter")
	fmt.Fprintf(m.w, "%s %d\n", name, v)
}

func (m metricWriter) gauge(name, help string, v int64) {
	m.header(name, help, "gauge")
	fmt.Fprintf(m.w, "%s %d\n", name, v)
}
