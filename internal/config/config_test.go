package config

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func mustCompile(t *testing.T, h Honeypot) Honeypot {
	t.Helper()
	if err := h.compile("ban"); err != nil {
		t.Fatalf("compile %+v: %v", h, err)
	}
	return h
}

func TestHoneypotMatches(t *testing.T) {
	cases := []struct {
		name string
		hp   Honeypot
		path string
		want bool
	}{
		{"prefix hit", Honeypot{Pattern: "/wp-admin", Match: "prefix"}, "/wp-admin/x", true},
		{"prefix boundary miss", Honeypot{Pattern: "/api", Match: "prefix"}, "/apixyz", false},
		{"prefix adds slash", Honeypot{Pattern: "wp-admin", Match: "prefix"}, "/wp-admin", true},
		{"contains .php", Honeypot{Pattern: ".php", Match: "contains"}, "/foo/bar.php?a=1", true},
		{"contains miss", Honeypot{Pattern: ".php", Match: "contains"}, "/foo/bar.html", false},
		{"suffix", Honeypot{Pattern: ".env", Match: "suffix"}, "/config/.env", true},
		{"glob hit", Honeypot{Pattern: "/cgi-bin/*", Match: "glob"}, "/cgi-bin/test.cgi", true},
		{"glob no cross slash", Honeypot{Pattern: "/cgi-bin/*", Match: "glob"}, "/cgi-bin/sub/x", false},
		{"regex git", Honeypot{Pattern: `\.(git|svn)(/|$)`, Match: "regex"}, "/.git/config", true},
		{"regex miss", Honeypot{Pattern: `\.(git|svn)(/|$)`, Match: "regex"}, "/legit", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hp := mustCompile(t, c.hp)
			if got := hp.Matches(c.path); got != c.want {
				t.Errorf("Matches(%q) = %v, want %v", c.path, got, c.want)
			}
		})
	}
}

func TestPrefixMatch(t *testing.T) {
	if !prefixMatch("/anything", "/") {
		t.Error(`"/" should match everything`)
	}
	if prefixMatch("/apixyz", "/api") {
		t.Error("prefix must respect path boundary")
	}
	if !prefixMatch("/api/v1", "/api") {
		t.Error("/api should match /api/v1")
	}
}

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		in      string
		wantURL string
		wantErr bool
	}{
		{"10.0.0.5:3000", "http://10.0.0.5:3000", false},
		{"10.0.0.5", "http://10.0.0.5", false},
		{"http://svc.cluster.local:8080", "http://svc.cluster.local:8080", false},
		{"https://10.0.0.5:8443", "https://10.0.0.5:8443", false},
		{"://bad", "", true},
	}
	for _, c := range cases {
		u, err := ParseUpstream(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseUpstream(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseUpstream(%q): %v", c.in, err)
			continue
		}
		if u.String() != c.wantURL {
			t.Errorf("ParseUpstream(%q) = %q, want %q", c.in, u.String(), c.wantURL)
		}
	}
}

func TestRouteMatchHost(t *testing.T) {
	cases := []struct {
		host string
		req  string
		want bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "API.example.com:443", true},
		{"api.example.com", "www.example.com", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "example.org", false},
	}
	for _, c := range cases {
		r := Route{Host: c.host}
		if got := r.MatchHost(c.req); got != c.want {
			t.Errorf("Route{%q}.MatchHost(%q) = %v, want %v", c.host, c.req, got, c.want)
		}
	}
}

func TestHoneypotUnmarshalShorthand(t *testing.T) {
	var h Honeypot
	if err := h.UnmarshalJSON([]byte(`"/wp-admin"`)); err != nil {
		t.Fatal(err)
	}
	if h.Pattern != "/wp-admin" || h.Match != "prefix" {
		t.Errorf("got %+v, want prefix /wp-admin", h)
	}
}

func TestWhitelistEntryUnmarshal(t *testing.T) {
	var c Config
	js := `{"whitelist":["1.2.3.4","107.214.211.0/24",{"ip":"9.9.9.0/24","no_log":true}]}`
	if err := json.Unmarshal([]byte(js), &c); err != nil {
		t.Fatal(err)
	}
	want := []WhitelistEntry{
		{IP: "1.2.3.4", NoLog: false},
		{IP: "107.214.211.0/24", NoLog: false},
		{IP: "9.9.9.0/24", NoLog: true},
	}
	if len(c.Whitelist) != len(want) {
		t.Fatalf("got %d entries, want %d", len(c.Whitelist), len(want))
	}
	for i, e := range c.Whitelist {
		if e != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, e, want[i])
		}
	}
	if specs := c.WhitelistSpecs(); len(specs) != 3 {
		t.Errorf("WhitelistSpecs = %v, want 3 entries", specs)
	}
	noLog := c.NoLogSpecs()
	if len(noLog) != 1 || noLog[0] != "9.9.9.0/24" {
		t.Errorf("NoLogSpecs = %v, want [9.9.9.0/24]", noLog)
	}
}

func loadJSON(t *testing.T, js string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestBlockAction(t *testing.T) {
	// Tarpit is the default action, with the hold cap and concurrency cap
	// defaulted too.
	c, err := loadJSON(t, `{"upstream":"10.0.0.1"}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockAction != "tarpit" {
		t.Errorf("default block_action = %q, want tarpit", c.BlockAction)
	}
	if c.TarpitDur() != 100*time.Second {
		t.Errorf("default tarpit cap = %v, want 100s", c.TarpitDur())
	}
	if c.TarpitMax != 512 {
		t.Errorf("default tarpit_max = %d, want 512", c.TarpitMax)
	}

	c, err = loadJSON(t, `{"upstream":"10.0.0.1","block_action":"tarpit","tarpit_duration":"30s"}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.BlockAction != "tarpit" || c.TarpitDur() != 30*time.Second {
		t.Errorf("got action=%q cap=%v, want tarpit/30s", c.BlockAction, c.TarpitDur())
	}

	if _, err = loadJSON(t, `{"upstream":"10.0.0.1","block_action":"nuke"}`); err == nil {
		t.Error("unknown block_action should be rejected")
	}
	if _, err = loadJSON(t, `{"upstream":"10.0.0.1","tarpit_duration":"-5s"}`); err == nil {
		t.Error("non-positive tarpit_duration should be rejected")
	}
}

func TestHoneypotsThatMatchRootAreRejected(t *testing.T) {
	for _, hp := range []string{
		`""`,
		`"/"`,
		`{"pattern":"", "match":"contains"}`,
		`{"pattern":"/", "match":"contains"}`,
		`{"pattern":"/", "match":"suffix"}`,
		`{"pattern":"/*", "match":"glob"}`,
		`{"pattern":".*", "match":"regex"}`,
	} {
		if _, err := loadJSON(t, `{"upstream":"10.0.0.1","honeypots":[`+hp+`]}`); err == nil {
			t.Errorf("honeypot %s would ban every visitor and should be rejected", hp)
		}
	}
}

func TestHoneypotsIgnoreCaseByDefault(t *testing.T) {
	c, err := loadJSON(t, `{"upstream":"10.0.0.1","honeypots":[
		"/wp-admin",
		{"pattern":".ENV","match":"suffix"},
		{"pattern":"\\.git(/|$)","match":"regex"},
		{"pattern":"/Secret","match":"prefix","case_sensitive":true}
	]}`)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want bool
	}{
		{"/WP-Admin/setup.php", true},
		{"/app/.env", true},
		{"/.GIT/config", true},
		{"/Secret/x", true},
		{"/secret/x", false}, // case_sensitive honeypot
		{"/index.html", false},
	}
	for _, c2 := range cases {
		if _, got := c.Honeypots.Match(c2.path); got != c2.want {
			t.Errorf("Match(%q) = %v, want %v", c2.path, got, c2.want)
		}
	}
	if p, ok := c.Honeypots.Match("/ok", "/WP-ADMIN"); !ok || p != "/wp-admin" {
		t.Errorf("Match should check every path form, got %q %v", p, ok)
	}
}

func TestNonPositiveDurationsRejected(t *testing.T) {
	for _, js := range []string{
		`{"upstream":"10.0.0.1","temp_ban":{"enabled":true,"window":"0s"}}`,
		`{"upstream":"10.0.0.1","temp_ban":{"enabled":true,"ban_duration":"-1m"}}`,
		`{"upstream":"10.0.0.1","request_log":{"ttl":"0s"}}`,
	} {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("config %s should be rejected", js)
		}
	}
}

func TestUnknownKeysRejected(t *testing.T) {
	for _, js := range []string{
		`{"upstream":"10.0.0.1","tempban":{"enabled":true}}`,
		`{"upstream":"10.0.0.1","temp_ban":{"enabled":true,"maxx":5}}`,
		`{"upstream":"10.0.0.1","honeypots":[{"pattern":"/x","mode":"contains"}]}`,
		`{"upstream":"10.0.0.1","whitelist":[{"ip":"1.2.3.4","nolog":true}]}`,
	} {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("config %s has an unknown key and should be rejected", js)
		}
	}
}

func TestNewFieldDefaults(t *testing.T) {
	c, err := loadJSON(t, `{"upstream":"10.0.0.1","temp_ban":{"enabled":true,"escalate_after":3},
		"stats":{"archive":{"dir":"/data/requests"}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.IPv6BanPrefix != 64 || c.CountryHeader != "Cf-Ipcountry" {
		t.Errorf("defaults: prefix=%d country=%q", c.IPv6BanPrefix, c.CountryHeader)
	}
	if c.TempBan.EscalateWindowDur() != 24*time.Hour {
		t.Errorf("escalate window = %v, want 24h", c.TempBan.EscalateWindowDur())
	}
	if c.Stats.Archive.RetentionDays != 30 || c.Stats.RecentRequests != 1000 {
		t.Errorf("archive defaults: retention=%d recent=%d", c.Stats.Archive.RetentionDays, c.Stats.RecentRequests)
	}

	for _, js := range []string{
		`{"upstream":"10.0.0.1","ipv6_ban_prefix":129}`,
		`{"upstream":"10.0.0.1","stats":{"archive":{}}}`,
		`{"upstream":"10.0.0.1","temp_ban":{"enabled":true,"escalate_after":-1}}`,
	} {
		if _, err := loadJSON(t, js); err == nil {
			t.Errorf("config %s should be rejected", js)
		}
	}
}

func TestReloadBlocked(t *testing.T) {
	a, _ := loadJSON(t, `{"upstream":"10.0.0.1","honeypots":["/a"]}`)
	b, _ := loadJSON(t, `{"upstream":"10.0.0.1","honeypots":["/b"],"whitelist":["1.2.3.4"]}`)
	if got := b.ReloadBlocked(a); len(got) != 0 {
		t.Errorf("honeypot/whitelist changes should reload live, got %v", got)
	}
	c, _ := loadJSON(t, `{"upstream":"10.0.0.2","listen":":1"}`)
	if got := c.ReloadBlocked(a); len(got) != 2 {
		t.Errorf("upstream+listen need a restart, got %v", got)
	}
}

func TestWhitelistFeeds(t *testing.T) {
	c, err := loadJSON(t, `{"upstream":"10.0.0.1","whitelist_feeds":[
		"https://openai.com/searchbot.json",
		{"url":"https://example.com/ips.txt","interval":"30m"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.WhitelistFeeds) != 2 {
		t.Fatalf("got %d feeds, want 2", len(c.WhitelistFeeds))
	}
	if f := c.WhitelistFeeds[0]; f.URL != "https://openai.com/searchbot.json" || f.IntervalDur() != 6*time.Hour {
		t.Errorf("shorthand feed = %q every %v, want default 6h", f.URL, f.IntervalDur())
	}
	if d := c.WhitelistFeeds[1].IntervalDur(); d != 30*time.Minute {
		t.Errorf("interval = %v, want 30m", d)
	}

	for _, bad := range []string{
		`["ftp://example.com/x"]`,
		`["not a url"]`,
		`[{"url":"https://example.com/x","interval":"10s"}]`,
		`[{"url":"https://example.com/x","intervall":"1h"}]`,
		`["https://example.com/x","https://example.com/x"]`,
	} {
		if _, err := loadJSON(t, `{"upstream":"10.0.0.1","whitelist_feeds":`+bad+`}`); err == nil {
			t.Errorf("whitelist_feeds %s should be rejected", bad)
		}
	}
}

func TestHeaderRulesMatchTheNamedHeader(t *testing.T) {
	c, err := loadJSON(t, `{"upstream":"10.0.0.1","honeypots":[
		{"header":"referer","pattern":"aocr.org","match":"contains","ban_for":"24h"},
		{"header":"User-Agent","pattern":"^evilbot/","match":"regex"},
		"/wp-admin"
	]}`)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Honeypots[0].Header; got != "Referer" {
		t.Errorf("header should be canonicalized, got %q", got)
	}
	if got := c.Honeypots[0].BanDuration(); got != 24*time.Hour {
		t.Errorf("BanDuration = %v, want 24h", got)
	}
	if got := c.Honeypots[2].BanDuration(); got != 0 {
		t.Errorf("a honeypot without ban_for must be permanent, got %v", got)
	}
	if got := c.Honeypots[0].Label(); got != "Referer: aocr.org" {
		t.Errorf("Label = %q", got)
	}

	hdr := func(k, v string) http.Header {
		h := http.Header{}
		h.Set(k, v)
		return h
	}
	cases := []struct {
		name string
		hdr  http.Header
		path string
		want string // Label of the rule expected to match, "" for none
	}{
		{"referer contains", hdr("Referer", "https://www.AOCR.org/some/page"), "/", "Referer: aocr.org"},
		{"other referer", hdr("Referer", "https://example.com/"), "/", ""},
		{"no headers", nil, "/", ""},
		{"ua regex", hdr("User-Agent", "EvilBot/1.0"), "/", "User-Agent: ^evilbot/"},
		{"ua regex not anchored elsewhere", hdr("User-Agent", "Mozilla evilbot/1.0"), "/", ""},
		{"header value never checked against path rules", hdr("Referer", "/wp-admin"), "/", ""},
		{"path rule still works", hdr("Referer", "https://example.com/"), "/wp-admin", "/wp-admin"},
	}
	for _, tc := range cases {
		h, ok := c.Honeypots.MatchRequest(tc.hdr, tc.path)
		got := ""
		if ok {
			got = h.Label()
		}
		if got != tc.want {
			t.Errorf("%s: matched %q, want %q", tc.name, got, tc.want)
		}
	}
	// Match (path only) ignores header rules entirely.
	if p, ok := c.Honeypots.Match("/wp-admin"); !ok || p != "/wp-admin" {
		t.Errorf("Match(/wp-admin) = %q %v", p, ok)
	}
}

func TestHeaderRulePrefixIsPlain(t *testing.T) {
	// Path-rule prefixes are boundary-aware and get a leading "/"; header-rule
	// prefixes are plain string prefixes on the header value.
	h := mustCompile(t, Honeypot{Header: "Referer", Pattern: "https://aocr", Match: "prefix"})
	if h.Pattern != "https://aocr" {
		t.Errorf("header prefix pattern must not be given a leading slash: %q", h.Pattern)
	}
	if !h.Matches("https://aocr.org/x") {
		t.Error("plain prefix should match")
	}
	if h.Matches("x https://aocr.org") {
		t.Error("prefix should not match mid-string")
	}
}

func TestRuleBanForValidation(t *testing.T) {
	for _, bad := range []string{
		`{"pattern":"/x","ban_for":"soon"}`,
		`{"pattern":"/x","ban_for":"0s"}`,
		`{"pattern":"/x","ban_for":"-1h"}`,
	} {
		if _, err := loadJSON(t, `{"upstream":"10.0.0.1","honeypots":[`+bad+`]}`); err == nil {
			t.Errorf("honeypot %s should be rejected", bad)
		}
	}
	if _, err := loadJSON(t, `{"upstream":"10.0.0.1","block_rules":[{"pattern":"/x","ban_for":"1h"}]}`); err == nil {
		t.Error("ban_for on a block rule should be rejected: block rules never ban")
	}
	if _, err := loadJSON(t, `{"upstream":"10.0.0.1","block_rules":[{"header":"Referer","pattern":"aocr.org","match":"contains"}]}`); err != nil {
		t.Errorf("valid block rule rejected: %v", err)
	}
}

func TestHeaderRulesThatMatchEverythingAreRejected(t *testing.T) {
	for _, rule := range []string{
		`{"header":"Referer","pattern":".*","match":"regex"}`,
		`{"header":"Referer","pattern":"^","match":"regex"}`,
		`{"header":"Referer","pattern":"*","match":"glob"}`,
	} {
		for _, list := range []string{"honeypots", "block_rules"} {
			if _, err := loadJSON(t, `{"upstream":"10.0.0.1","`+list+`":[`+rule+`]}`); err == nil {
				t.Errorf("%s %s matches every request with the header and should be rejected", list, rule)
			}
		}
	}
	// Block rules get the same site-root guard as honeypots.
	if _, err := loadJSON(t, `{"upstream":"10.0.0.1","block_rules":["/"]}`); err == nil {
		t.Error("a block rule matching / would block every visitor and should be rejected")
	}
}

func TestBlockRulesReloadLive(t *testing.T) {
	a, _ := loadJSON(t, `{"upstream":"10.0.0.1","block_rules":["/a"]}`)
	b, _ := loadJSON(t, `{"upstream":"10.0.0.1","block_rules":["/b"]}`)
	if got := a.ReloadBlocked(b); len(got) != 0 {
		t.Errorf("block_rules changes should reload live, got %v", got)
	}
}

// The repo's example config.json is what the README points people at; it must
// always load.
func TestExampleConfigLoads(t *testing.T) {
	c, err := Load(filepath.Join("..", "..", "config.json"))
	if err != nil {
		t.Fatalf("config.json in the repo root does not load: %v", err)
	}
	if len(c.Honeypots) == 0 || len(c.BlockRules) == 0 {
		t.Errorf("example config should demonstrate honeypots and block_rules, got %d/%d", len(c.Honeypots), len(c.BlockRules))
	}
}
