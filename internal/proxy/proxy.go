package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync/atomic"
	"time"

	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/history"
	"thorngate/internal/monitor"
	"thorngate/internal/stats"
)

// WAF is an http.Handler that blacklists honeypot hitters and reverse-proxies
// everything else to the default upstream (or a hostname override).
type WAF struct {
	cfg       *config.Config
	bl        *blacklist.Blacklist
	def       *httputil.ReverseProxy // default upstream for all traffic
	defTarget string                 // resolved default upstream URL, for logging
	routes    []hostRoute            // optional hostname overrides
	mon       *monitor.Monitor       // nil unless temp_ban is enabled
	hist      *history.Tracker       // nil unless request_log is enabled
	stats     *stats.Collector       // nil unless stats is enabled
	noLog     []*net.IPNet           // whitelist entries flagged no_log: skip stats/history

	tarpitting atomic.Int64 // connections currently held by the tarpit
}

type hostRoute struct {
	route  config.Route
	proxy  *httputil.ReverseProxy
	target string // resolved upstream URL, for logging
}

// New builds the WAF handler from config and a blacklist store.
func New(cfg *config.Config, bl *blacklist.Blacklist) (*WAF, error) {
	w := &WAF{cfg: cfg, bl: bl, noLog: blacklist.ParseNets(cfg.NoLogSpecs())}

	def, defTarget, err := newProxy(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	w.def, w.defTarget = def, defTarget

	for _, r := range cfg.Routes {
		rp, target, err := newProxy(r.Upstream)
		if err != nil {
			return nil, err
		}
		w.routes = append(w.routes, hostRoute{route: r, proxy: rp, target: target})
	}

	if cfg.TempBan != nil && cfg.TempBan.Enabled {
		win := cfg.TempBan.WindowDur()
		w.mon = monitor.New(cfg.TempBan.Max, win)
		go func() {
			for range time.Tick(win) {
				w.mon.Sweep()
			}
		}()
	}

	if cfg.RequestLog != nil && cfg.RequestLog.Enabled() {
		rl := cfg.RequestLog
		w.hist = history.New(rl.Depth, rl.MaxIPs, rl.TTLDur())
		go func() {
			for range time.Tick(rl.TTLDur()) {
				w.hist.Sweep()
			}
		}()
	}

	if cfg.Stats != nil && cfg.Stats.Enabled() {
		w.stats = stats.New(cfg.Stats.WindowMinutes, cfg.Stats.RecentRequests)
	}

	return w, nil
}

// Stats returns the traffic collector, or nil if stats are disabled. The admin
// portal reads it to render the dashboard.
func (w *WAF) Stats() *stats.Collector { return w.stats }

// newProxy builds a single-host reverse proxy for an upstream config value. It
// also returns the resolved target URL so requests can be logged with the
// upstream they were routed to.
func newProxy(upstream string) (*httputil.ReverseProxy, string, error) {
	target, err := config.ParseUpstream(upstream)
	if err != nil {
		return nil, "", err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("upstream error host=%s path=%s upstream=%s: %v", req.Host, req.URL.Path, target, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}
	return rp, target.String(), nil
}

func (w *WAF) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip := w.clientIP(r)

	// no_log whitelist entries (e.g. your own monitors) are kept out of the
	// stats feed and request history entirely. They can never be blacklisted,
	// so blacklist/honeypot/temp-ban bookkeeping is irrelevant for them too.
	quiet := len(w.noLog) > 0 && blacklist.Matches(w.noLog, ip)

	// 1. Already blacklisted? Denied with no upstream contact.
	if w.bl.IsBlocked(ip) {
		action := w.denyAction()
		if w.stats != nil {
			w.stats.Request(true)
			w.observeDenied(ip, r, "blocked", action)
		}
		w.deny(action, rw, r)
		return
	}
	if w.stats != nil && !quiet {
		w.stats.Request(false)
	}

	// 2. Honeypot hit? Blacklist and deny.
	if pattern, hit := w.honeypot(r.URL.Path); hit {
		if w.bl.Add(ip, "honeypot", pattern) {
			log.Printf("BLACKLISTED ip=%s path=%s honeypot=%s ua=%q total=%d",
				ip, r.URL.Path, pattern, r.UserAgent(), w.bl.Count())
			w.dumpHistory(ip, "honeypot")
			if w.stats != nil {
				w.stats.Honeypot()
			}
		}
		action := w.denyAction()
		if w.stats != nil && !quiet {
			w.observeDenied(ip, r, "honeypot", action)
		}
		w.deny(action, rw, r)
		return
	}

	// 3. Hostname override? Otherwise fall through to the default upstream.
	up, target := w.upstreamFor(r)

	// With no response-inspecting feature enabled (or a quiet no_log IP), proxy
	// directly with no response wrapping.
	if quiet || (w.mon == nil && w.hist == nil && w.stats == nil) {
		up.ServeHTTP(rw, r)
		return
	}

	sw := &statusWriter{ResponseWriter: rw, status: http.StatusOK}
	up.ServeHTTP(sw, r)
	w.recordRequest(ip, r, sw.status, target)
	if w.stats != nil {
		w.stats.Status(sw.status)
		w.stats.Bytes(sw.bytes)
		w.observe(ip, r, sw.status, "proxied", target, sw.bytes)
	}
	if w.mon != nil {
		w.monitorResponse(ip, sw.status)
	}
}

// observe records a request in the stats recent-requests feed. Caller has
// already checked w.stats != nil. upstream is empty (and bytes zero) when the
// request never reached one (blocked / honeypot).
func (w *WAF) observe(ip string, r *http.Request, status int, outcome, upstream string, bytes int64) {
	w.stats.Observe(stats.Event{
		Time:     time.Now().UTC(),
		IP:       ip,
		Method:   r.Method,
		Host:     r.Host,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		Status:   status,
		Outcome:  outcome,
		Upstream: upstream,
		Bytes:    bytes,
	})
}

// recordRequest remembers a request that reached an upstream so it can be
// dumped for context if this IP is later blacklisted. No-op when disabled.
func (w *WAF) recordRequest(ip string, r *http.Request, status int, upstream string) {
	if w.hist == nil {
		return
	}
	w.hist.Record(ip, history.Record{
		Time:     time.Now().UTC(),
		Method:   r.Method,
		Host:     r.Host,
		Path:     r.URL.Path,
		Query:    r.URL.RawQuery,
		UA:       r.UserAgent(),
		Status:   status,
		Upstream: upstream,
	})
}

// dumpHistory logs the recent requests this IP made before being blacklisted,
// to help research emerging attack patterns, then forgets them. No-op when
// request logging is disabled or there is no history for the IP.
func (w *WAF) dumpHistory(ip, reason string) {
	if w.hist == nil {
		return
	}
	recs := w.hist.History(ip)
	for i, rec := range recs {
		log.Printf("  history ip=%s reason=%s %d/%d at=%s method=%s host=%q path=%q query=%q upstream=%q status=%d ua=%q",
			ip, reason, i+1, len(recs), rec.Time.Format(time.RFC3339),
			rec.Method, rec.Host, rec.Path, rec.Query, rec.Upstream, rec.Status, rec.UA)
	}
	w.hist.Forget(ip)
}

// upstreamFor picks the proxy for a request — the first route whose host
// pattern matches, else the default upstream — and returns the resolved
// upstream URL alongside it for logging.
func (w *WAF) upstreamFor(r *http.Request) (*httputil.ReverseProxy, string) {
	for i := range w.routes {
		if w.routes[i].route.MatchHost(r.Host) {
			return w.routes[i].proxy, w.routes[i].target
		}
	}
	return w.def, w.defTarget
}

// monitorResponse records a strike for bad responses and applies a temporary
// ban once an IP crosses the configured threshold.
func (w *WAF) monitorResponse(ip string, status int) {
	tb := w.cfg.TempBan
	if !tb.IsBadCode(status) {
		return
	}
	if w.mon.Strike(ip) && w.bl.AddTemp(ip, "rate-limit", tb.BanDur()) {
		log.Printf("TEMP-BANNED ip=%s for=%s (>=%d bad responses in %s, last=%d) total=%d",
			ip, tb.BanDuration, tb.Max, tb.Window, status, w.bl.Count())
		w.dumpHistory(ip, "rate-limit")
		if w.stats != nil {
			w.stats.TempBan()
		}
	}
}

// clientIP returns the real external IP. Behind a Cloudflare Tunnel this comes
// from the configured header (Cf-Connecting-Ip); otherwise it falls back to the
// TCP peer address.
func (w *WAF) clientIP(r *http.Request) string {
	if h := r.Header.Get(w.cfg.ClientIPHeader); h != "" {
		// Header may be a single IP (CF) or a comma list (XFF).
		if i := strings.IndexByte(h, ','); i >= 0 {
			h = h[:i]
		}
		return strings.TrimSpace(h)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (w *WAF) honeypot(reqPath string) (string, bool) {
	for i := range w.cfg.Honeypots {
		if w.cfg.Honeypots[i].Matches(reqPath) {
			return w.cfg.Honeypots[i].Pattern, true
		}
	}
	return "", false
}

// denyAction decides how a blocked request will be ended — "forbidden",
// "drop", or "tarpit" — so stats can record what actually happens. Choosing
// "tarpit" reserves one of the TarpitMax concurrent slots (so an attacker who
// notices the tarpit can't exhaust file descriptors); when none is free the
// request degrades to "drop". A reserved slot is released by deny.
func (w *WAF) denyAction() string {
	switch w.cfg.BlockAction {
	case "drop":
		return "drop"
	case "tarpit":
		if w.tarpitting.Add(1) > int64(w.cfg.TarpitMax) {
			w.tarpitting.Add(-1)
			return "drop"
		}
		return "tarpit"
	default:
		return "forbidden"
	}
}

// deny ends a blocked request with the action denyAction picked: a plain 403,
// an immediate connection drop, or a tarpit that holds the connection open —
// never responding — until the client gives up or the configured cap elapses.
func (w *WAF) deny(action string, rw http.ResponseWriter, r *http.Request) {
	switch action {
	case "drop":
		drop(rw)
	case "tarpit":
		t := time.NewTimer(w.cfg.TarpitDur())
		select {
		case <-r.Context().Done(): // client hung up first
		case <-t.C:
		}
		t.Stop()
		w.tarpitting.Add(-1)
		drop(rw)
	default:
		forbidden(rw)
	}
}

// observeDenied records a denied (blocked/honeypot) request in the stats feed.
// Caller has already checked w.stats != nil. A written 403 is recorded by its
// status; drop/tarpit write nothing, so status is 0 and Deny says what happened.
func (w *WAF) observeDenied(ip string, r *http.Request, outcome, action string) {
	status := 0
	if action == "forbidden" {
		status = http.StatusForbidden
	}
	w.stats.Observe(stats.Event{
		Time:    time.Now().UTC(),
		IP:      ip,
		Method:  r.Method,
		Host:    r.Host,
		Path:    r.URL.Path,
		Query:   r.URL.RawQuery,
		Status:  status,
		Outcome: outcome,
		Deny:    denyLabel(action),
	})
}

// denyLabel is the Deny value recorded in stats: empty for a written 403.
func denyLabel(action string) string {
	if action == "forbidden" {
		return ""
	}
	return action
}

// drop severs the client connection without writing a response. If the
// connection can't be hijacked (e.g. HTTP/2, or a test recorder), panicking
// with ErrAbortHandler makes net/http abort the response without a stack trace.
func drop(rw http.ResponseWriter) {
	if hj, ok := rw.(http.Hijacker); ok {
		if conn, _, err := hj.Hijack(); err == nil {
			_ = conn.Close()
			return
		}
	}
	panic(http.ErrAbortHandler)
}

func forbidden(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusForbidden)
	_, _ = rw.Write([]byte("403 Forbidden\n"))
}

// statusWriter wraps http.ResponseWriter to capture the response status code
// for temp-ban monitoring and the body size for traffic stats. It forwards
// Flush so streaming responses still work.
type statusWriter struct {
	http.ResponseWriter
	status      int
	bytes       int64 // body bytes written; hijacked-connection traffic is not counted
	wroteHeader bool
}

func (s *statusWriter) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	s.wroteHeader = true // implicit 200 if WriteHeader was never called
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusWriter) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack lets the underlying connection be taken over for protocol upgrades
// (WebSockets, SignalR). ReverseProxy requires the ResponseWriter to implement
// http.Hijacker before it will switch protocols; since we wrap it, we must
// forward the call. A hijacked connection bypasses WriteHeader, so we record a
// 101 status for monitoring/history.
func (s *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("upstream: ResponseWriter does not support hijacking")
	}
	if !s.wroteHeader {
		s.status = http.StatusSwitchingProtocols
		s.wroteHeader = true
	}
	return hj.Hijack()
}
