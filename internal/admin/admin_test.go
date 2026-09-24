package admin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"thorngate/internal/archive"
	"thorngate/internal/auth"
	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/stats"
)

// token is the legacy API token, still accepted alongside session logins.
const token = "secret-token"

func newServer(t *testing.T) (*httptest.Server, *blacklist.Blacklist) {
	t.Helper()
	bl, err := blacklist.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	au, err := auth.New("")
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(Handler(Options{
		Blacklist: bl, Stats: stats.New(60, 100), Auth: au, APIToken: token, Metrics: true,
	})), bl
}

func do(t *testing.T, srv *httptest.Server, method, path, body, tok string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestRequiresToken(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	if res := do(t, srv, "GET", "/admin/blacklist", "", ""); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: got %d, want 401", res.StatusCode)
	}
	if res := do(t, srv, "GET", "/admin/blacklist", "", "wrong"); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token: got %d, want 401", res.StatusCode)
	}
}

func TestAddListRemove(t *testing.T) {
	srv, bl := newServer(t)
	defer srv.Close()

	if res := do(t, srv, "POST", "/admin/blacklist", `{"ip":"1.2.3.4","reason":"test"}`, token); res.StatusCode != http.StatusOK {
		t.Fatalf("add: got %d, want 200", res.StatusCode)
	}
	if !bl.IsBlocked("1.2.3.4") {
		t.Fatal("IP should be blocked after add")
	}

	if res := do(t, srv, "DELETE", "/admin/blacklist/1.2.3.4", "", token); res.StatusCode != http.StatusOK {
		t.Fatalf("remove: got %d, want 200", res.StatusCode)
	}
	if bl.IsBlocked("1.2.3.4") {
		t.Fatal("IP should be unblocked after remove")
	}
}

func TestAddListRemoveCIDR(t *testing.T) {
	srv, bl := newServer(t)
	defer srv.Close()

	if res := do(t, srv, "POST", "/admin/blacklist", `{"ip":"1.2.3.0/24","reason":"subnet"}`, token); res.StatusCode != http.StatusOK {
		t.Fatalf("add CIDR: got %d, want 200", res.StatusCode)
	}
	if !bl.IsBlocked("1.2.3.99") {
		t.Fatal("an IP in the added CIDR should be blocked")
	}

	if res := do(t, srv, "DELETE", "/admin/blacklist/1.2.3.0/24", "", token); res.StatusCode != http.StatusOK {
		t.Fatalf("remove CIDR: got %d, want 200", res.StatusCode)
	}
	if bl.IsBlocked("1.2.3.99") {
		t.Fatal("CIDR ban should be gone after remove")
	}
}

func TestAddRejectsBadIP(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	if res := do(t, srv, "POST", "/admin/blacklist", `{"ip":"not-an-ip"}`, token); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad ip: got %d, want 400", res.StatusCode)
	}
}

func TestPageServedWithoutAuth(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	// The SPA (index.html) is served for any non-API path, unauthenticated.
	if res := do(t, srv, "GET", "/", "", ""); res.StatusCode != http.StatusOK {
		t.Errorf("page: got %d, want 200", res.StatusCode)
	}
}

func TestLoginFlow(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	// Wrong credentials are rejected.
	if res := do(t, srv, "POST", "/admin/login", `{"username":"admin","password":"nope"}`, ""); res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login: got %d, want 401", res.StatusCode)
	}

	// Default admin/admin succeeds and returns a session token.
	res := do(t, srv, "POST", "/admin/login", `{"username":"admin","password":"admin"}`, "")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", res.StatusCode)
	}
	var out struct {
		Token    string `json:"token"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Token == "" {
		t.Fatal("expected a session token")
	}

	// While the default password is in place, the session may only change it.
	if r := do(t, srv, "GET", "/admin/blacklist", "", out.Token); r.StatusCode != http.StatusForbidden {
		t.Errorf("default-password session: got %d, want 403", r.StatusCode)
	}
	if r := do(t, srv, "POST", "/admin/password",
		`{"current_password":"admin","new_password":"a-real-password"}`, out.Token); r.StatusCode != http.StatusOK {
		t.Fatalf("password change: got %d, want 200", r.StatusCode)
	}

	// Now the session token authorizes API calls.
	if r := do(t, srv, "GET", "/admin/blacklist", "", out.Token); r.StatusCode != http.StatusOK {
		t.Errorf("session auth: got %d, want 200", r.StatusCode)
	}

	// Logout invalidates it.
	if r := do(t, srv, "POST", "/admin/logout", "", out.Token); r.StatusCode != http.StatusOK {
		t.Errorf("logout: got %d, want 200", r.StatusCode)
	}
	if r := do(t, srv, "GET", "/admin/blacklist", "", out.Token); r.StatusCode != http.StatusUnauthorized {
		t.Errorf("post-logout: got %d, want 401", r.StatusCode)
	}
}

func TestLoginLockoutReturns429(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	for i := 0; i < 5; i++ {
		do(t, srv, "POST", "/admin/login", `{"username":"admin","password":"nope"}`, "")
	}
	res := do(t, srv, "POST", "/admin/login", `{"username":"admin","password":"admin"}`, "")
	if res.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked-out login: got %d, want 429", res.StatusCode)
	}
	if res.Header.Get("Retry-After") == "" {
		t.Error("429 should carry a Retry-After header")
	}
	// The legacy API token is unaffected by the login lockout.
	if r := do(t, srv, "GET", "/admin/blacklist", "", token); r.StatusCode != http.StatusOK {
		t.Errorf("token auth during lockout: got %d, want 200", r.StatusCode)
	}
}

func TestOversizedBodyRejected(t *testing.T) {
	srv, _ := newServer(t)
	defer srv.Close()

	body := `{"ip":"1.2.3.4","reason":"` + strings.Repeat("x", 100<<10) + `"}`
	if res := do(t, srv, "POST", "/admin/blacklist", body, token); res.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: got %d, want 400", res.StatusCode)
	}
}

func TestBanKeysNormalized(t *testing.T) {
	srv, bl := newServer(t)
	defer srv.Close()

	do(t, srv, "POST", "/admin/blacklist", `{"ip":" 2001:DB8::1 "}`, token)
	if !bl.IsBlocked("2001:db8::1") {
		t.Fatal("admin ban should be stored under the canonical address")
	}
	res := do(t, srv, "DELETE", "/admin/blacklist/2001:0DB8::0001", "", token)
	var out struct {
		Removed bool `json:"removed"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if !out.Removed {
		t.Fatal("unban should accept any spelling of the address")
	}
}

// serverWith builds an admin server over a collector seeded with events and an
// optional archive.
func serverWith(t *testing.T, st *stats.Collector, arch *archive.Archive, extra func(*Options)) (*httptest.Server, *blacklist.Blacklist) {
	t.Helper()
	bl, err := blacklist.New("", []string{"10.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	au, _ := auth.New("")
	o := Options{Blacklist: bl, Stats: st, Archive: arch, Auth: au, APIToken: token, Metrics: true}
	if extra != nil {
		extra(&o)
	}
	srv := httptest.NewServer(Handler(o))
	t.Cleanup(srv.Close)
	return srv, bl
}

func getJSON(t *testing.T, srv *httptest.Server, path string, v any) int {
	t.Helper()
	res := do(t, srv, "GET", path, "", token)
	defer res.Body.Close()
	if v != nil {
		_ = json.NewDecoder(res.Body).Decode(v)
	}
	return res.StatusCode
}

func seeded() *stats.Collector {
	st := stats.New(60, 100)
	now := time.Now().UTC()
	for i, e := range []stats.Event{
		{IP: "1.1.1.1", Path: "/", Outcome: "proxied", Status: 200, Country: "US"},
		{IP: "1.1.1.1", Path: "/login", Outcome: "proxied", Status: 401},
		{IP: "6.6.6.6", Path: "/.env", Outcome: "honeypot", UA: "zgrab"},
	} {
		e.Time = now.Add(time.Duration(i) * time.Second)
		st.Observe(e)
	}
	return st
}

func TestRequestsFilteringAndBannedFlag(t *testing.T) {
	for _, withArchive := range []bool{false, true} {
		t.Run(fmt.Sprintf("archive=%v", withArchive), func(t *testing.T) {
			st := seeded()
			var arch *archive.Archive
			if withArchive {
				var err error
				if arch, err = archive.Open(t.TempDir(), 24*time.Hour); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(arch.Close)
				p, _ := st.Query(stats.Filter{}, 1, 50)
				for i := len(p.Events) - 1; i >= 0; i-- {
					arch.Append(p.Events[i])
				}
			}
			srv, bl := serverWith(t, st, arch, nil)
			bl.Add("6.6.6.6", "honeypot", "/.env")

			var out struct {
				Archive bool            `json:"archive"`
				Total   int             `json:"total"`
				Events  []stats.Event   `json:"events"`
				Banned  map[string]bool `json:"banned"`
			}
			getJSON(t, srv, "/admin/requests?ip=1.1.1.1", &out)
			if out.Total != 2 || out.Archive != withArchive {
				t.Fatalf("ip filter: %+v", out)
			}
			getJSON(t, srv, "/admin/requests?q=ZGRAB", &out)
			if out.Total != 1 || !out.Banned["6.6.6.6"] {
				t.Fatalf("text filter / banned flag: %+v", out)
			}
			getJSON(t, srv, "/admin/requests?status=4xx&range=1h", &out)
			if out.Total != 1 {
				t.Fatalf("status filter: %+v", out)
			}
			if code := getJSON(t, srv, "/admin/requests?ip=bogus", nil); code != http.StatusBadRequest {
				t.Errorf("bad ip filter: got %d, want 400", code)
			}
			if code := getJSON(t, srv, "/admin/requests?range=forever", nil); code != http.StatusBadRequest {
				t.Errorf("bad range: got %d, want 400", code)
			}
		})
	}
}

func TestTopHourlyAndIPProfile(t *testing.T) {
	srv, bl := serverWith(t, seeded(), nil, nil)
	bl.Add("1.1.1.0/24", "manual", "")

	var top struct {
		IPs    []stats.Counted `json:"ips"`
		Banned map[string]bool `json:"banned"`
	}
	getJSON(t, srv, "/admin/top?range=1h", &top)
	if len(top.IPs) != 2 || top.IPs[0].Key != "1.1.1.1" || !top.Banned["1.1.1.1"] {
		t.Fatalf("top: %+v", top)
	}

	var hourly struct {
		Series []stats.Bucket `json:"series"`
	}
	getJSON(t, srv, "/admin/hourly?range=2h", &hourly)
	if len(hourly.Series) < 2 {
		t.Fatalf("hourly: %+v", hourly)
	}

	var prof struct {
		IP          string           `json:"ip"`
		Whitelisted bool             `json:"whitelisted"`
		Ban         *blacklist.Entry `json:"ban"`
		Summary     stats.IPSummary  `json:"summary"`
	}
	getJSON(t, srv, "/admin/ip/1.1.1.1", &prof)
	if prof.Ban == nil || prof.Ban.IP != "1.1.1.0/24" || prof.Summary.Requests != 2 || prof.Summary.Country != "US" {
		t.Fatalf("profile should show the covering range ban and traffic: %+v", prof)
	}
	getJSON(t, srv, "/admin/ip/10.9.9.9", &prof)
	if !prof.Whitelisted || prof.Ban != nil {
		t.Fatalf("whitelisted profile: %+v", prof)
	}
	if code := getJSON(t, srv, "/admin/ip/1.2.3.0%2F24", nil); code != http.StatusBadRequest {
		t.Errorf("profile of a range: got %d, want 400", code)
	}
}

func TestTempBanFromAPI(t *testing.T) {
	srv, bl := serverWith(t, nil, nil, nil)
	do(t, srv, "POST", "/admin/blacklist", `{"ip":"3.3.3.3","duration":"2h"}`, token)
	e, ok := bl.Lookup("3.3.3.3")
	if !ok || e.Until.IsZero() || time.Until(e.Until) > 2*time.Hour {
		t.Fatalf("expected a ~2h temp ban, got %+v", e)
	}
	do(t, srv, "POST", "/admin/blacklist", `{"ip":"3.3.3.4","duration":"7d"}`, token)
	if e, _ := bl.Lookup("3.3.3.4"); time.Until(e.Until) < 6*24*time.Hour {
		t.Fatalf("7d ban too short: %+v", e)
	}
	if res := do(t, srv, "POST", "/admin/blacklist", `{"ip":"3.3.3.5","duration":"soon"}`, token); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad duration: got %d, want 400", res.StatusCode)
	}
}

func TestImportExport(t *testing.T) {
	srv, bl := serverWith(t, nil, nil, nil)

	text := "# a public blocklist\n1.2.3.4\n5.6.7.0/24 ; comment\n\nnot-an-ip\n10.9.9.9\n"
	res := do(t, srv, "POST", "/admin/blacklist/import", text, token)
	var out struct {
		Added   int      `json:"added"`
		Skipped int      `json:"skipped"`
		Invalid []string `json:"invalid"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if out.Added != 2 || out.Skipped != 1 || len(out.Invalid) != 1 {
		t.Fatalf("text import: %+v", out)
	}

	res = do(t, srv, "GET", "/admin/blacklist/export", "", token)
	if !strings.Contains(res.Header.Get("Content-Disposition"), "attachment") {
		t.Error("export should download as a file")
	}
	var exported []blacklist.Entry
	_ = json.NewDecoder(res.Body).Decode(&exported)
	if len(exported) != 2 {
		t.Fatalf("export: %+v", exported)
	}

	// Round trip into a fresh server.
	srv2, bl2 := serverWith(t, nil, nil, nil)
	body, _ := json.Marshal(exported)
	do(t, srv2, "POST", "/admin/blacklist/import", string(body), token)
	if bl2.Count() != bl.Count() || !bl2.IsBlocked("5.6.7.8") {
		t.Fatalf("JSON import round trip: %v", bl2.List())
	}
}

func TestWhitelistReloadAndMetrics(t *testing.T) {
	reloaded := false
	srv, _ := serverWith(t, seeded(), nil, func(o *Options) {
		o.Whitelist = func() []config.WhitelistEntry {
			return []config.WhitelistEntry{{IP: "10.9.9.9", NoLog: true}}
		}
		o.Reload = func() ([]string, error) { reloaded = true; return []string{"upstream"}, nil }
		o.Tarpitting = func() int64 { return 3 }
	})

	var wl []config.WhitelistEntry
	getJSON(t, srv, "/admin/whitelist", &wl)
	if len(wl) != 1 || !wl[0].NoLog {
		t.Fatalf("whitelist: %+v", wl)
	}

	res := do(t, srv, "POST", "/admin/reload", "", token)
	var rl struct {
		Restart []string `json:"restart_required"`
	}
	_ = json.NewDecoder(res.Body).Decode(&rl)
	if !reloaded || len(rl.Restart) != 1 {
		t.Fatalf("reload: called=%v %+v", reloaded, rl)
	}

	// Metrics need no auth.
	res = do(t, srv, "GET", "/metrics", "", "")
	body, _ := io.ReadAll(res.Body)
	for _, want := range []string{
		"thorngate_requests_total 0",
		`thorngate_responses_total{class="2xx"}`,
		"thorngate_blacklist_entries 0",
		"thorngate_tarpit_connections 3",
	} {
		if !strings.Contains(string(body), want) {
			t.Errorf("metrics missing %q:\n%s", want, body)
		}
	}
}
