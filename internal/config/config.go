package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"regexp"
	"strings"
	"time"
)

// Config is the top-level configuration loaded from a JSON file.
type Config struct {
	// Listen is the address the WAF listens on, e.g. ":8765".
	Listen string `json:"listen"`

	// ClientIPHeader is the header that holds the real external client IP.
	// Behind a Cloudflare Tunnel this is "Cf-Connecting-Ip".
	ClientIPHeader string `json:"client_ip_header"`

	// BlacklistFile is where blacklisted IPs are persisted as JSON.
	// In k8s point this at a mounted volume so it survives restarts.
	BlacklistFile string `json:"blacklist_file"`

	// Honeypots are patterns that should never be hit by a legitimate client.
	// Any external IP that matches one is blacklisted immediately.
	Honeypots []Honeypot `json:"honeypots"`

	// Whitelist are IPs that are never blacklisted, e.g. your own office IP or
	// health-check sources. Each entry may be a single IP ("1.2.3.4"), a CIDR
	// ("10.0.0.0/8"), or an octet wildcard ("107.214.211.*"). An entry may also
	// be an object to set per-entry options, e.g.
	// { "ip": "107.214.211.*", "no_log": true }.
	Whitelist []WhitelistEntry `json:"whitelist"`

	// Upstream is the default internal target that ALL traffic is proxied to
	// unless a hostname route below matches. Accepts an IP/host with optional
	// port and optional scheme, e.g. "10.0.0.10:8080", "10.0.0.10",
	// or "http://my-app.svc.cluster.local:8080" (scheme defaults to http).
	Upstream string `json:"upstream"`

	// Routes are OPTIONAL hostname overrides. A request whose Host matches a
	// route is sent to that route's upstream; everything else falls through to
	// the default Upstream above.
	Routes []Route `json:"routes"`

	// TempBan is OPTIONAL. When enabled, an IP that produces too many "bad"
	// response codes within a time window is temporarily blacklisted.
	TempBan *TempBan `json:"temp_ban"`

	// Admin is OPTIONAL. When enabled, a token-protected admin API + web page
	// is served on a SEPARATE port for managing the blacklist. Never attach
	// this port to the Cloudflare tunnel — reach it via kubectl port-forward.
	Admin *Admin `json:"admin"`

	// RequestLog is OPTIONAL and ON by default. It remembers the last few
	// requests each client IP made and dumps them to the log when that IP is
	// blacklisted, so the recon leading up to a ban can be researched. Memory
	// is bounded; set "disabled": true to turn it off.
	RequestLog *RequestLog `json:"request_log"`

	// Stats is OPTIONAL and ON by default. It keeps in-memory traffic counters
	// (totals + a rolling per-minute series) for the admin portal. The overhead
	// is a few atomic increments per request; set "disabled": true to turn it
	// off. Counters are memory-only and reset on restart.
	Stats *Stats `json:"stats"`
}

// Stats tunes the in-memory traffic counters surfaced by the admin portal.
// The zero value is enabled with defaults.
type Stats struct {
	// Disabled turns the feature off entirely (no counters, zero overhead).
	Disabled bool `json:"disabled"`
	// WindowMinutes is how many minutes the traffic-over-time series covers.
	// Default 60.
	WindowMinutes int `json:"window_minutes"`
	// RecentRequests caps how many recent requests the dashboard's request feed
	// can hold (IP + path + outcome). The portal shows up to the last 24 hours
	// of it, paginated. Default 5000 (~1 MB); set negative to omit the feed.
	RecentRequests int `json:"recent_requests"`
}

func (s *Stats) compile() error {
	if s.WindowMinutes <= 0 {
		s.WindowMinutes = 60
	}
	if s.RecentRequests == 0 {
		s.RecentRequests = 5000
	}
	return nil
}

// Enabled reports whether traffic counters should be kept.
func (s *Stats) Enabled() bool { return !s.Disabled }

// RequestLog tunes the in-memory per-IP request history that is dumped to the
// log whenever an IP is blacklisted. The zero value is enabled with defaults.
type RequestLog struct {
	// Disabled turns the feature off entirely (no per-IP tracking, zero
	// overhead). Left false the feature is on.
	Disabled bool `json:"disabled"`
	// Depth is how many recent requests to keep per IP. Default 10.
	Depth int `json:"depth"`
	// MaxIPs caps how many distinct IPs are tracked at once; the
	// least-recently active IP is evicted past this. Default 4096.
	MaxIPs int `json:"max_ips"`
	// TTL drops history for IPs idle longer than this (Go duration). Default "15m".
	TTL string `json:"ttl"`

	ttl time.Duration
}

func (r *RequestLog) compile() error {
	if r.Depth <= 0 {
		r.Depth = 10
	}
	if r.MaxIPs <= 0 {
		r.MaxIPs = 4096
	}
	if r.TTL == "" {
		r.TTL = "15m"
	}
	d, err := time.ParseDuration(r.TTL)
	if err != nil {
		return fmt.Errorf("ttl %q: %w", r.TTL, err)
	}
	r.ttl = d
	return nil
}

// Enabled reports whether per-IP request history should be kept.
func (r *RequestLog) Enabled() bool { return !r.Disabled }

// TTLDur returns the parsed idle-eviction window.
func (r *RequestLog) TTLDur() time.Duration { return r.ttl }

// Admin configures the admin portal (React SPA + JSON API).
type Admin struct {
	Enabled bool `json:"enabled"`
	// Listen is the admin port, default ":9000". Keep it cluster-internal.
	Listen string `json:"listen"`
	// Token is an OPTIONAL legacy bearer token accepted by the API for scripted
	// access, alongside interactive login. If empty, it falls back to the
	// THORNGATE_ADMIN_TOKEN environment variable. Leave unset to disable it and
	// rely solely on username/password login.
	Token string `json:"token"`
	// CredentialsFile is where the admin username + hashed password are stored.
	// Defaults to "admin_credentials.json". A fresh file is seeded with
	// admin/admin; change the password from the portal's Settings tab. Point it
	// at a persistent volume (e.g. /data/admin_credentials.json) so the change
	// survives restarts.
	CredentialsFile string `json:"credentials_file"`
}

// TempBan auto-bans IPs that generate too many bad responses (e.g. scanners
// hammering 404s). Bans expire on their own after BanDuration.
type TempBan struct {
	Enabled bool `json:"enabled"`
	// StatusCodes that count as "bad". Default: 401, 403, 404, 429.
	StatusCodes []int `json:"status_codes"`
	// Max bad responses allowed within Window before a ban kicks in. Default 20.
	Max int `json:"max"`
	// Window is the sliding window for counting, e.g. "1m". Default "1m".
	Window string `json:"window"`
	// BanDuration is how long the temporary ban lasts, e.g. "15m". Default "15m".
	BanDuration string `json:"ban_duration"`

	window time.Duration
	banDur time.Duration
	codes  map[int]bool
}

func (t *TempBan) compile() error {
	if t.Max <= 0 {
		t.Max = 20
	}
	if len(t.StatusCodes) == 0 {
		t.StatusCodes = []int{401, 403, 404, 429}
	}
	if t.Window == "" {
		t.Window = "1m"
	}
	if t.BanDuration == "" {
		t.BanDuration = "15m"
	}
	w, err := time.ParseDuration(t.Window)
	if err != nil {
		return fmt.Errorf("window %q: %w", t.Window, err)
	}
	d, err := time.ParseDuration(t.BanDuration)
	if err != nil {
		return fmt.Errorf("ban_duration %q: %w", t.BanDuration, err)
	}
	t.window, t.banDur = w, d
	t.codes = make(map[int]bool, len(t.StatusCodes))
	for _, c := range t.StatusCodes {
		t.codes[c] = true
	}
	return nil
}

// WindowDur returns the parsed counting window.
func (t *TempBan) WindowDur() time.Duration { return t.window }

// BanDur returns the parsed ban duration.
func (t *TempBan) BanDur() time.Duration { return t.banDur }

// IsBadCode reports whether a response status counts toward a ban.
func (t *TempBan) IsBadCode(code int) bool { return t.codes[code] }

// Route sends a specific hostname to a specific internal upstream.
type Route struct {
	// Host matches the request Host header (case-insensitive, port ignored).
	// A leading "*." is a wildcard, e.g. "*.example.com" matches any subdomain
	// (a.example.com, a.b.example.com) but not the apex example.com itself.
	Host string `json:"host"`
	// Upstream is the internal target for this host. Same format as the
	// top-level Upstream (IP / host:port / full URL; scheme defaults to http).
	Upstream string `json:"upstream"`
}

// WhitelistEntry is a single whitelist rule. In JSON it may be either:
//
//	"107.214.211.*"                                 // shorthand: just the address
//	{ "ip": "107.214.211.*", "no_log": true }       // address plus options
//
// IP accepts a single IP, a CIDR, or an octet wildcard. NoLog, when set, also
// excludes the matched IPs from request logging and traffic stats (handy for
// your own monitors / health checks that would otherwise clutter the feed).
type WhitelistEntry struct {
	IP    string `json:"ip"`
	NoLog bool   `json:"no_log"`
}

// UnmarshalJSON lets a whitelist entry be a bare string or a full object.
func (e *WhitelistEntry) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		e.IP = s
		e.NoLog = false
		return nil
	}
	type raw WhitelistEntry // avoid recursing into this method
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*e = WhitelistEntry(r)
	return nil
}

// WhitelistSpecs returns the address specs of every whitelist entry, for
// building the never-blacklist set.
func (c *Config) WhitelistSpecs() []string {
	specs := make([]string, 0, len(c.Whitelist))
	for _, e := range c.Whitelist {
		specs = append(specs, e.IP)
	}
	return specs
}

// NoLogSpecs returns the address specs of whitelist entries flagged no_log, for
// building the set of IPs excluded from logging and stats.
func (c *Config) NoLogSpecs() []string {
	var specs []string
	for _, e := range c.Whitelist {
		if e.NoLog {
			specs = append(specs, e.IP)
		}
	}
	return specs
}

// Honeypot is a request matcher. In JSON it may be either:
//
//	"/wp-admin"                                  // shorthand: prefix match
//	{ "pattern": ".php", "match": "contains" }   // explicit match mode
//
// Supported match modes: "prefix" (default), "contains", "suffix",
// "glob" (path.Match against the full path), "regex".
type Honeypot struct {
	Pattern string `json:"pattern"`
	Match   string `json:"match"`

	re *regexp.Regexp // compiled, for match == "regex"
}

// UnmarshalJSON lets a honeypot be a bare string (prefix) or a full object.
func (h *Honeypot) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		h.Pattern = s
		h.Match = "prefix"
		return nil
	}
	type raw Honeypot // avoid recursing into this method
	var r raw
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	*h = Honeypot(r)
	if h.Match == "" {
		h.Match = "prefix"
	}
	return nil
}

func (h *Honeypot) compile() error {
	switch h.Match {
	case "prefix":
		if !strings.HasPrefix(h.Pattern, "/") {
			h.Pattern = "/" + h.Pattern
		}
	case "contains", "suffix":
		// nothing to precompile
	case "glob":
		if _, err := path.Match(h.Pattern, "/"); err != nil {
			return fmt.Errorf("invalid glob %q: %w", h.Pattern, err)
		}
	case "regex":
		re, err := regexp.Compile(h.Pattern)
		if err != nil {
			return fmt.Errorf("invalid regex %q: %w", h.Pattern, err)
		}
		h.re = re
	default:
		return fmt.Errorf("unknown match mode %q (want prefix|contains|suffix|glob|regex)", h.Match)
	}
	if h.Pattern == "" {
		return fmt.Errorf("honeypot pattern is empty")
	}
	return nil
}

// Matches reports whether a request path trips this honeypot.
func (h *Honeypot) Matches(reqPath string) bool {
	switch h.Match {
	case "prefix":
		return prefixMatch(reqPath, h.Pattern)
	case "contains":
		return strings.Contains(reqPath, h.Pattern)
	case "suffix":
		return strings.HasSuffix(reqPath, h.Pattern)
	case "glob":
		ok, _ := path.Match(h.Pattern, reqPath)
		return ok
	case "regex":
		return h.re.MatchString(reqPath)
	}
	return false
}

// prefixMatch matches on path boundaries so "/api" matches "/api" and "/api/x"
// but not "/apixyz".
func prefixMatch(reqPath, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(reqPath, prefix) {
		return false
	}
	rest := reqPath[len(prefix):]
	return rest == "" || rest[0] == '/'
}

// Load reads and validates a config file.
func Load(filePath string) (*Config, error) {
	b, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if c.Listen == "" {
		c.Listen = ":8765"
	}
	if c.ClientIPHeader == "" {
		c.ClientIPHeader = "Cf-Connecting-Ip"
	}
	if c.Upstream == "" {
		return nil, fmt.Errorf("config: a default upstream is required")
	}
	if _, err := ParseUpstream(c.Upstream); err != nil {
		return nil, fmt.Errorf("config: upstream %q: %w", c.Upstream, err)
	}
	for i, r := range c.Routes {
		if r.Host == "" || r.Upstream == "" {
			return nil, fmt.Errorf("config: route %d needs both host and upstream", i)
		}
		if _, err := ParseUpstream(r.Upstream); err != nil {
			return nil, fmt.Errorf("config: route %d upstream %q: %w", i, r.Upstream, err)
		}
	}
	for i := range c.Honeypots {
		if err := c.Honeypots[i].compile(); err != nil {
			return nil, fmt.Errorf("config: honeypot %d: %w", i, err)
		}
	}
	if c.TempBan != nil && c.TempBan.Enabled {
		if err := c.TempBan.compile(); err != nil {
			return nil, fmt.Errorf("config: temp_ban: %w", err)
		}
	}
	if c.RequestLog == nil {
		c.RequestLog = &RequestLog{} // on by default
	}
	if err := c.RequestLog.compile(); err != nil {
		return nil, fmt.Errorf("config: request_log: %w", err)
	}
	if c.Stats == nil {
		c.Stats = &Stats{} // on by default
	}
	if err := c.Stats.compile(); err != nil {
		return nil, fmt.Errorf("config: stats: %w", err)
	}
	if c.Admin != nil && c.Admin.Enabled {
		if c.Admin.Listen == "" {
			c.Admin.Listen = ":9000"
		}
		if c.Admin.Token == "" {
			c.Admin.Token = os.Getenv("THORNGATE_ADMIN_TOKEN")
		}
		if c.Admin.CredentialsFile == "" {
			c.Admin.CredentialsFile = "admin_credentials.json"
		}
	}

	return &c, nil
}

// ParseUpstream turns a config upstream value into a URL the proxy can use.
// It accepts a full URL ("http://10.0.0.5:3000"), a host:port ("10.0.0.5:3000"),
// or a bare host/IP ("10.0.0.5"); the scheme defaults to http.
func ParseUpstream(s string) (*url.URL, error) {
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host")
	}
	return u, nil
}

// MatchHost reports whether a request host matches this route. Matching is
// case-insensitive and ignores any port. A route Host of "*.example.com"
// matches any single-or-multi-level subdomain of example.com.
func (r *Route) MatchHost(host string) bool {
	host = normalizeHost(host)
	want := strings.ToLower(r.Host)
	if suffix, ok := strings.CutPrefix(want, "*."); ok {
		// Subdomains only, not the apex (DNS-standard wildcard semantics).
		return strings.HasSuffix(host, "."+suffix)
	}
	return host == want
}

// normalizeHost lowercases a Host header value and strips any :port.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}
