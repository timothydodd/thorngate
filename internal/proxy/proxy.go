package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/history"
	"thorngate/internal/monitor"
	"thorngate/internal/stats"
)

// Archiver receives every observed request for long-term storage
// (internal/archive). Append must not block.
type Archiver interface {
	Append(stats.Event)
}

// WAF is an http.Handler that blacklists honeypot hitters and reverse-proxies
// everything else to the default upstream (or a hostname override).
type WAF struct {
	// rules holds the settings Reload can swap while serving. Each request
	// loads it once, so it never sees a mix of old and new settings.
	rules atomic.Pointer[rules]

	bl        *blacklist.Blacklist
	def       *httputil.ReverseProxy // default upstream for all traffic
	defTarget string                 // resolved default upstream URL, for logging
	routes    []hostRoute            // optional hostname overrides
	tempBan   *config.TempBan        // nil unless temp_ban is enabled
	mon       *monitor.Monitor       // nil unless temp_ban is enabled
	esc       *monitor.Monitor       // nil unless temp_ban.escalate_after > 0
	hist      *history.Tracker       // nil unless request_log is enabled
	stats     *stats.Collector       // nil unless stats is enabled
	arch      Archiver               // nil unless stats.archive is set

	tarpitting atomic.Int64  // connections currently held by the tarpit
	stop       chan struct{} // closed by ReleaseTarpits at shutdown
	stopOnce   sync.Once
}

// rules are the live-reloadable settings: everything read from cfg on the
// request path (honeypots, block action, tarpit, client IP / country headers,
// ipv6_ban_prefix) plus the no_log set derived from the whitelist.
type rules struct {
	cfg   *config.Config
	noLog []*net.IPNet // whitelist entries flagged no_log: skip stats/history
}

type hostRoute struct {
	route  config.Route
	proxy  *httputil.ReverseProxy
	target string // resolved upstream URL, for logging
}

// New builds the WAF handler from config and a blacklist store.
func New(cfg *config.Config, bl *blacklist.Blacklist) (*WAF, error) {
	w := &WAF{bl: bl, stop: make(chan struct{})}
	w.rules.Store(newRules(cfg))

	tr := newTransport()
	def, defTarget, err := newProxy(cfg.Upstream, tr)
	if err != nil {
		return nil, err
	}
	w.def, w.defTarget = def, defTarget

	for _, r := range cfg.Routes {
		rp, target, err := newProxy(r.Upstream, tr)
		if err != nil {
			return nil, err
		}
		w.routes = append(w.routes, hostRoute{route: r, proxy: rp, target: target})
	}

	if cfg.TempBan != nil && cfg.TempBan.Enabled {
		tb := cfg.TempBan
		w.tempBan = tb
		w.mon = monitor.New(tb.Max, tb.WindowDur())
		go sweepEvery(tb.WindowDur(), w.mon.Sweep)
		if tb.EscalateAfter > 0 {
			w.esc = monitor.New(tb.EscalateAfter, tb.EscalateWindowDur())
			go sweepEvery(min(tb.EscalateWindowDur(), time.Hour), w.esc.Sweep)
		}
	}

	if cfg.RequestLog != nil && cfg.RequestLog.Enabled() {
		rl := cfg.RequestLog
		w.hist = history.New(rl.Depth, rl.MaxIPs, rl.TTLDur())
		go sweepEvery(rl.TTLDur(), w.hist.Sweep)
	}

	if cfg.Stats != nil && cfg.Stats.Enabled() {
		w.stats = stats.New(cfg.Stats.WindowMinutes, cfg.Stats.RecentRequests)
	}

	return w, nil
}

func newRules(cfg *config.Config) *rules {
	return &rules{cfg: cfg, noLog: blacklist.ParseNets(cfg.NoLogSpecs())}
}

func sweepEvery(d time.Duration, sweep func()) {
	for range time.Tick(d) {
		sweep()
	}
}

// SetArchive attaches long-term request storage. Call before serving; requests
// are archived only when stats are enabled.
func (w *WAF) SetArchive(a Archiver) { w.arch = a }

// Reload swaps in the live-reloadable settings from cfg (see rules) and the
// blacklist's whitelist. Settings that need a restart are left as they were;
// config.ReloadBlocked reports which ones differ.
func (w *WAF) Reload(cfg *config.Config) {
	w.rules.Store(newRules(cfg))
	w.bl.SetWhitelist(cfg.WhitelistSpecs())
}

// Stats returns the traffic collector, or nil if stats are disabled. The admin
// portal reads it to render the dashboard.
func (w *WAF) Stats() *stats.Collector { return w.stats }

// Tarpitting returns how many connections the tarpit is holding right now.
func (w *WAF) Tarpitting() int64 { return w.tarpitting.Load() }

// ReleaseTarpits ends every tarpit hold (current and future) immediately. It is
// registered with http.Server.RegisterOnShutdown so held connections — up to
// tarpit_duration each — don't outlast the graceful-shutdown timeout.
func (w *WAF) ReleaseTarpits() {
	w.stopOnce.Do(func() { close(w.stop) })
}

// newTransport returns the upstream transport shared by every proxy. Unlike
// http.DefaultTransport (2 idle connections per host), it keeps enough idle
// connections that proxied requests under load reuse them instead of opening a
// fresh upstream connection each time.
func newTransport() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 512
	t.MaxIdleConnsPerHost = 128
	return t
}

// newProxy builds a single-host reverse proxy for an upstream config value. It
// also returns the resolved target URL so requests can be logged with the
// upstream they were routed to.
func newProxy(upstream string, tr http.RoundTripper) (*httputil.ReverseProxy, string, error) {
	target, err := config.ParseUpstream(upstream)
	if err != nil {
		return nil, "", err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = tr
	rp.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("upstream error host=%s path=%s upstream=%s: %v", req.Host, req.URL.Path, target, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}
	return rp, target.String(), nil
}

func (w *WAF) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rl := w.rules.Load()
	c := rl.cfg
	ip := clientIP(r, c.ClientIPHeader)

	// no_log whitelist entries (e.g. your own monitors) are kept out of the
	// stats feed and request history entirely. They can never be blacklisted,
	// so blacklist/honeypot/temp-ban bookkeeping is irrelevant for them too.
	quiet := len(rl.noLog) > 0 && blacklist.Matches(rl.noLog, ip)

	// 1. Already blacklisted? Denied with no upstream contact.
	if w.bl.IsBlocked(ip) {
		action := w.denyAction(c)
		if w.stats != nil {
			w.stats.Request(true)
			w.observeDenied(c, ip, r, "blocked", action)
		}
		w.deny(c, action, rw, r)
		return
	}
	if w.stats != nil && !quiet {
		w.stats.Request(false)
	}

	// 2. Honeypot hit? Blacklist (the IP, or its IPv6 range) and deny.
	if pattern, hit := honeypot(c, r.URL.Path); hit {
		if key := w.banKeyFor(c, ip); key != "" && w.bl.Add(key, "honeypot", pattern) {
			log.Printf("BLACKLISTED ip=%s%s path=%s honeypot=%s ua=%q total=%d",
				ip, rangeNote(ip, key), r.URL.Path, pattern, r.UserAgent(), w.bl.Count())
			w.dumpHistory(ip, "honeypot")
			if w.stats != nil {
				w.stats.Honeypot()
			}
		}
		action := w.denyAction(c)
		if w.stats != nil && !quiet {
			w.observeDenied(c, ip, r, "honeypot", action)
		}
		w.deny(c, action, rw, r)
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
		e := w.event(c, ip, r)
		e.Status, e.Outcome, e.Upstream, e.Bytes = sw.status, "proxied", target, sw.bytes
		w.observe(e)
	}
	if w.mon != nil {
		w.monitorResponse(c, ip, sw.status)
	}
}

// Caps on event fields, so one oversized request can't bloat the in-memory
// feed or the archive.
const (
	maxPathLen  = 2048
	maxQueryLen = 1024
	maxUALen    = 512
)

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// event fills in the request-derived fields of a feed event.
func (w *WAF) event(c *config.Config, ip string, r *http.Request) stats.Event {
	return stats.Event{
		Time:    time.Now().UTC(),
		IP:      ip,
		Method:  r.Method,
		Host:    r.Host,
		Path:    truncate(r.URL.Path, maxPathLen),
		Query:   truncate(r.URL.RawQuery, maxQueryLen),
		Country: truncate(r.Header.Get(c.CountryHeader), 8),
		UA:      truncate(r.UserAgent(), maxUALen),
	}
}

// observe records an event in the stats feed and, when enabled, the archive.
// Caller has already checked w.stats != nil.
func (w *WAF) observe(e stats.Event) {
	w.stats.Observe(e)
	if w.arch != nil {
		w.arch.Append(e)
	}
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

// banKeyFor returns what an automatic ban of ip should cover — the IP, or its
// IPv6 range per ipv6_ban_prefix — or "" if ip is whitelisted: a whitelisted
// client's neighbours in its IPv6 range must not be banned on its account.
func (w *WAF) banKeyFor(c *config.Config, ip string) string {
	if w.bl.IsWhitelisted(ip) {
		return ""
	}
	return blacklist.BanKey(ip, c.IPv6BanPrefix)
}

// rangeNote is a log suffix naming the range banned when it is wider than ip.
func rangeNote(ip, key string) string {
	if key == ip {
		return ""
	}
	return " range=" + key
}

// monitorResponse records a strike for bad responses and applies a temporary
// ban once an IP (or IPv6 range) crosses the configured threshold. With
// escalation on, enough temp-bans within the escalation window make it
// permanent.
func (w *WAF) monitorResponse(c *config.Config, ip string, status int) {
	tb := w.tempBan
	if !tb.IsBadCode(status) {
		return
	}
	// Strikes are counted per ban key, so an IPv6 scanner rotating through
	// its /64 accumulates them as one client.
	key := w.banKeyFor(c, ip)
	if key == "" {
		return
	}
	if !w.mon.Strike(key) || !w.bl.AddTemp(key, "rate-limit", tb.BanDur()) {
		return
	}
	log.Printf("TEMP-BANNED ip=%s%s for=%s (>=%d bad responses in %s, last=%d) total=%d",
		ip, rangeNote(ip, key), tb.BanDuration, tb.Max, tb.Window, status, w.bl.Count())
	w.dumpHistory(ip, "rate-limit")
	if w.stats != nil {
		w.stats.TempBan()
	}
	if w.esc != nil && w.esc.Strike(key) && w.bl.Add(key, "repeat-offender", "") {
		log.Printf("ESCALATED ip=%s%s to a permanent ban (%d temp-bans within %s)",
			ip, rangeNote(ip, key), tb.EscalateAfter, tb.EscalateWindow)
		if w.stats != nil {
			w.stats.Escalated()
		}
	}
}

// clientIP returns the real external IP. Behind a Cloudflare Tunnel this comes
// from the configured header (Cf-Connecting-Ip); otherwise it falls back to the
// TCP peer address. Addresses are canonicalized ("2001:DB8::1" ->
// "2001:db8::1") so each client maps to exactly one blacklist key. A header
// value that isn't an IP is returned as-is rather than falling back to the
// peer, which is cloudflared itself and must never be banned.
func clientIP(r *http.Request, header string) string {
	if h := r.Header.Get(header); h != "" {
		// Header may be a single IP (CF) or a comma list (XFF).
		if i := strings.IndexByte(h, ','); i >= 0 {
			h = h[:i]
		}
		return canonicalIP(strings.TrimSpace(h))
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return canonicalIP(r.RemoteAddr)
	}
	return canonicalIP(host)
}

func canonicalIP(s string) string {
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return s
}

// honeypot checks the request path against the honeypots. The cleaned path is
// checked too: "/x/../wp-admin", "//wp-admin" and (on IIS) "/x\..\wp-admin"
// all reach the upstream's /wp-admin though the raw path doesn't start with it.
func honeypot(c *config.Config, reqPath string) (string, bool) {
	if clean := cleanPath(reqPath); clean != reqPath {
		return c.Honeypots.Match(reqPath, clean)
	}
	return c.Honeypots.Match(reqPath)
}

// cleanPath resolves "." / ".." / duplicate slashes (and backslashes, which IIS
// treats as separators) the way an upstream would, keeping a trailing slash.
func cleanPath(p string) string {
	if strings.IndexByte(p, '\\') >= 0 {
		p = strings.ReplaceAll(p, "\\", "/")
	}
	if p == "" || p[0] != '/' {
		p = "/" + p
	}
	c := path.Clean(p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// denyAction decides how a blocked request will be ended — "forbidden",
// "drop", or "tarpit" — so stats can record what actually happens. Choosing
// "tarpit" reserves one of the TarpitMax concurrent slots (so an attacker who
// notices the tarpit can't exhaust file descriptors); when none is free the
// request degrades to "drop". A reserved slot is released by deny.
func (w *WAF) denyAction(c *config.Config) string {
	switch c.BlockAction {
	case "drop":
		return "drop"
	case "tarpit":
		if w.tarpitting.Add(1) > int64(c.TarpitMax) {
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
func (w *WAF) deny(c *config.Config, action string, rw http.ResponseWriter, r *http.Request) {
	switch action {
	case "drop":
		drop(rw)
	case "tarpit":
		t := time.NewTimer(c.TarpitDur())
		select {
		case <-r.Context().Done(): // client hung up first
		case <-w.stop: // server shutting down
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
func (w *WAF) observeDenied(c *config.Config, ip string, r *http.Request, outcome, action string) {
	e := w.event(c, ip, r)
	if action == "forbidden" {
		e.Status = http.StatusForbidden
	}
	e.Outcome, e.Deny = outcome, denyLabel(action)
	w.observe(e)
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
