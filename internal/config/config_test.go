package config

import (
	"encoding/json"
	"testing"
)

func mustCompile(t *testing.T, h Honeypot) Honeypot {
	t.Helper()
	if err := h.compile(); err != nil {
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
