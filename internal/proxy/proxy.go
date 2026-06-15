package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/history"
	"thorngate/internal/monitor"
)

// WAF is an http.Handler that blacklists honeypot hitters and reverse-proxies
// everything else to the default upstream (or a hostname override).
type WAF struct {
	cfg    *config.Config
	bl     *blacklist.Blacklist
	def    *httputil.ReverseProxy // default upstream for all traffic
	routes []hostRoute            // optional hostname overrides
	mon    *monitor.Monitor       // nil unless temp_ban is enabled
	hist   *history.Tracker       // nil unless request_log is enabled
}

type hostRoute struct {
	route config.Route
	proxy *httputil.ReverseProxy
}

// New builds the WAF handler from config and a blacklist store.
func New(cfg *config.Config, bl *blacklist.Blacklist) (*WAF, error) {
	w := &WAF{cfg: cfg, bl: bl}

	def, err := newProxy(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	w.def = def

	for _, r := range cfg.Routes {
		rp, err := newProxy(r.Upstream)
		if err != nil {
			return nil, err
		}
		w.routes = append(w.routes, hostRoute{route: r, proxy: rp})
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

	return w, nil
}

// newProxy builds a single-host reverse proxy for an upstream config value.
func newProxy(upstream string) (*httputil.ReverseProxy, error) {
	target, err := config.ParseUpstream(upstream)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log.Printf("upstream error host=%s path=%s: %v", req.Host, req.URL.Path, err)
		http.Error(rw, "Bad Gateway", http.StatusBadGateway)
	}
	return rp, nil
}

func (w *WAF) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip := w.clientIP(r)

	// 1. Already blacklisted? Hard 403, no upstream contact.
	if w.bl.IsBlocked(ip) {
		forbidden(rw)
		return
	}

	// 2. Honeypot hit? Blacklist and 403.
	if path, hit := w.honeypot(r.URL.Path); hit {
		if w.bl.Add(ip, "honeypot", path) {
			log.Printf("BLACKLISTED ip=%s honeypot=%s ua=%q total=%d",
				ip, path, r.UserAgent(), w.bl.Count())
			w.dumpHistory(ip, "honeypot")
		}
		forbidden(rw)
		return
	}

	// 3. Hostname override? Otherwise fall through to the default upstream.
	up := w.upstreamFor(r)

	// With neither temp-ban monitoring nor request logging, proxy directly
	// with no response wrapping.
	if w.mon == nil && w.hist == nil {
		up.ServeHTTP(rw, r)
		return
	}

	sw := &statusWriter{ResponseWriter: rw, status: http.StatusOK}
	up.ServeHTTP(sw, r)
	w.recordRequest(ip, r, sw.status)
	if w.mon != nil {
		w.monitorResponse(ip, sw.status)
	}
}

// recordRequest remembers a request that reached an upstream so it can be
// dumped for context if this IP is later blacklisted. No-op when disabled.
func (w *WAF) recordRequest(ip string, r *http.Request, status int) {
	if w.hist == nil {
		return
	}
	w.hist.Record(ip, history.Record{
		Time:   time.Now().UTC(),
		Method: r.Method,
		Host:   r.Host,
		Path:   r.URL.Path,
		Query:  r.URL.RawQuery,
		UA:     r.UserAgent(),
		Status: status,
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
		log.Printf("  history ip=%s reason=%s %d/%d at=%s method=%s host=%q path=%q query=%q status=%d ua=%q",
			ip, reason, i+1, len(recs), rec.Time.Format(time.RFC3339),
			rec.Method, rec.Host, rec.Path, rec.Query, rec.Status, rec.UA)
	}
	w.hist.Forget(ip)
}

func (w *WAF) upstreamFor(r *http.Request) *httputil.ReverseProxy {
	for i := range w.routes {
		if w.routes[i].route.MatchHost(r.Host) {
			return w.routes[i].proxy
		}
	}
	return w.def
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

func forbidden(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusForbidden)
	_, _ = rw.Write([]byte("403 Forbidden\n"))
}

// statusWriter wraps http.ResponseWriter to capture the response status code for
// temp-ban monitoring. It forwards Flush so streaming responses still work.
type statusWriter struct {
	http.ResponseWriter
	status      int
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
	return s.ResponseWriter.Write(b)
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
