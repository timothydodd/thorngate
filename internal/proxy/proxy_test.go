package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/stats"
)

// newWAF builds a WAF whose default upstream is the given backend handler. The
// extra string is spliced into the config JSON (e.g. honeypots, temp_ban).
func newWAF(t *testing.T, backend http.HandlerFunc, extra string) (*WAF, *blacklist.Blacklist) {
	t.Helper()
	be := httptest.NewServer(backend)
	t.Cleanup(be.Close)

	js := fmt.Sprintf(`{"upstream":%q%s}`, be.URL, extra)
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	bl, err := blacklist.New("", cfg.WhitelistSpecs())
	if err != nil {
		t.Fatal(err)
	}
	w, err := New(cfg, bl)
	if err != nil {
		t.Fatalf("new WAF: %v", err)
	}
	return w, bl
}

// reqFrom builds a request to path that appears to come from clientIP via the
// Cf-Connecting-Ip header (the default client_ip_header).
func reqFrom(clientIP, path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Header.Set("Cf-Connecting-Ip", clientIP)
	return r
}

func okBackend(hits *int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(hits, 1)
		_, _ = w.Write([]byte("ok"))
	}
}

func TestProxiesNormalRequest(t *testing.T) {
	var hits int32
	w, _ := newWAF(t, okBackend(&hits), "")

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, reqFrom("1.2.3.4", "/"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Fatalf("body = %q, want ok", rec.Body.String())
	}
	if hits != 1 {
		t.Fatalf("backend hits = %d, want 1", hits)
	}
}

func TestBlockedIPGetsForbiddenWithoutUpstream(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"block_action":"forbidden"`)
	bl.Add("6.6.6.6", "manual", "")

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, reqFrom("6.6.6.6", "/"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if hits != 0 {
		t.Fatalf("a blocked IP must never reach the upstream (hits = %d)", hits)
	}
}

func TestHoneypotHitBlacklistsClient(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/wp-admin"],"block_action":"forbidden"`)

	// Hitting the honeypot is forbidden and does not reach the upstream.
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, reqFrom("7.7.7.7", "/wp-admin"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("honeypot status = %d, want 403", rec.Code)
	}
	if !bl.IsBlocked("7.7.7.7") {
		t.Fatal("client should be blacklisted after a honeypot hit")
	}
	// The same client is now blocked on a perfectly normal path.
	rec = httptest.NewRecorder()
	w.ServeHTTP(rec, reqFrom("7.7.7.7", "/"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blacklisted client status = %d, want 403", rec.Code)
	}
	if hits != 0 {
		t.Fatalf("honeypot/blocked traffic must not reach upstream (hits = %d)", hits)
	}
}

func TestClientIPComesFromHeaderNotPeer(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/wp-admin"],"block_action":"forbidden"`)

	r := reqFrom("8.8.8.8", "/wp-admin")
	r.RemoteAddr = "203.0.113.9:5555" // the TCP peer differs from the CF header
	w.ServeHTTP(httptest.NewRecorder(), r)

	if !bl.IsBlocked("8.8.8.8") {
		t.Fatal("the header IP should be blacklisted")
	}
	if bl.IsBlocked("203.0.113.9") {
		t.Fatal("the TCP peer must not be blacklisted when a header IP is present")
	}
}

func TestTempBanAfterRepeatedBadResponses(t *testing.T) {
	notFound := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
	extra := `,"block_action":"forbidden","temp_ban":{"enabled":true,"max":3,"window":"1m","ban_duration":"15m","status_codes":[404]}`
	w, bl := newWAF(t, notFound, extra)

	const ip = "4.4.4.4"
	for i := 0; i < 3; i++ {
		if bl.IsBlocked(ip) {
			t.Fatalf("IP banned too early, after %d strikes", i)
		}
		w.ServeHTTP(httptest.NewRecorder(), reqFrom(ip, "/missing"))
	}
	if !bl.IsBlocked(ip) {
		t.Fatal("IP should be temp-banned after reaching the bad-response threshold")
	}

	// Once banned, traffic is short-circuited to 403.
	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, reqFrom(ip, "/missing"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status after ban = %d, want 403", rec.Code)
	}
}

// denyClient makes a real HTTP request (recorders can't be hijacked) and
// reports whether the server ended the connection without any response.
func denyClient(t *testing.T, srvURL, ip, path string) error {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srvURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cf-Connecting-Ip", ip)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatalf("got a %d response, want the connection dropped with no response", resp.StatusCode)
	}
	return err
}

func TestBlockActionDrop(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/wp-admin"],"block_action":"drop"`)
	srv := httptest.NewServer(w)
	t.Cleanup(srv.Close)

	// Honeypot hit: connection dropped, IP blacklisted, upstream untouched.
	denyClient(t, srv.URL, "5.5.5.5", "/wp-admin")
	if !bl.IsBlocked("5.5.5.5") {
		t.Fatal("client should be blacklisted after a honeypot hit")
	}
	// Every later request from that IP is dropped too.
	denyClient(t, srv.URL, "5.5.5.5", "/")
	if hits != 0 {
		t.Fatalf("dropped traffic must not reach upstream (hits = %d)", hits)
	}
}

func TestBlockActionTarpitHoldsThenDrops(t *testing.T) {
	var hits int32
	extra := `,"honeypots":["/wp-admin"],"block_action":"tarpit","tarpit_duration":"150ms"`
	w, _ := newWAF(t, okBackend(&hits), extra)
	srv := httptest.NewServer(w)
	t.Cleanup(srv.Close)

	start := time.Now()
	denyClient(t, srv.URL, "3.3.3.3", "/wp-admin")
	if held := time.Since(start); held < 150*time.Millisecond {
		t.Fatalf("connection ended after %v, want it held for at least the 150ms tarpit cap", held)
	}
	if hits != 0 {
		t.Fatalf("tarpitted traffic must not reach upstream (hits = %d)", hits)
	}
}

func TestTarpitMaxFallsBackToDrop(t *testing.T) {
	var hits int32
	extra := `,"honeypots":["/wp-admin"],"block_action":"tarpit","tarpit_duration":"5s","tarpit_max":1`
	w, _ := newWAF(t, okBackend(&hits), extra)
	srv := httptest.NewServer(w)
	t.Cleanup(srv.Close)

	// Fill the single tarpit slot, then wait until it is actually held.
	go func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/wp-admin", nil)
		req.Header.Set("Cf-Connecting-Ip", "2.2.2.2")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	for i := 0; w.tarpitting.Load() == 0; i++ {
		if i > 100 {
			t.Fatal("first request never entered the tarpit")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Over the cap: the next blocked request must be dropped immediately,
	// not held for the 5s tarpit duration.
	start := time.Now()
	denyClient(t, srv.URL, "2.2.2.3", "/wp-admin")
	if held := time.Since(start); held > 2*time.Second {
		t.Fatalf("over-cap request held for %v, want an immediate drop", held)
	}
}

func TestHoneypotMatchesUncleanAndMixedCasePaths(t *testing.T) {
	for _, p := range []string{"//wp-admin", "/x/../wp-admin/", "/x/%5C..%5Cwp-admin", "/WP-Admin/setup.php"} {
		t.Run(p, func(t *testing.T) {
			var hits int32
			w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/wp-admin"],"block_action":"forbidden"`)
			w.ServeHTTP(httptest.NewRecorder(), reqFrom("7.7.7.7", p))
			if !bl.IsBlocked("7.7.7.7") {
				t.Fatalf("%q reaches the upstream's /wp-admin and should trip the honeypot", p)
			}
			if hits != 0 {
				t.Fatalf("honeypot request must not reach upstream (hits = %d)", hits)
			}
		})
	}
}

func TestClientIPIsCanonicalized(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/wp-admin"],"block_action":"forbidden"`)
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("2001:DB8:0::1", "/wp-admin"))
	if !bl.IsBlocked("2001:db8::1") {
		t.Fatal("the ban should be keyed by the canonical IPv6 form")
	}
}

func TestReleaseTarpitsEndsHolds(t *testing.T) {
	var hits int32
	extra := `,"honeypots":["/wp-admin"],"block_action":"tarpit","tarpit_duration":"10s"`
	w, _ := newWAF(t, okBackend(&hits), extra)
	srv := httptest.NewServer(w)
	t.Cleanup(srv.Close)

	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/wp-admin", nil)
		req.Header.Set("Cf-Connecting-Ip", "4.4.4.4")
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
		done <- time.Since(start)
	}()
	for i := 0; w.tarpitting.Load() == 0; i++ {
		if i > 100 {
			t.Fatal("request never entered the tarpit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	w.ReleaseTarpits()
	select {
	case held := <-done:
		if held > 5*time.Second {
			t.Fatalf("tarpit held %v after release", held)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReleaseTarpits did not end the held connection")
	}
}

// recordingArchive collects archived events.
type recordingArchive struct {
	mu     sync.Mutex
	events []stats.Event
}

func (a *recordingArchive) Append(e stats.Event) {
	a.mu.Lock()
	a.events = append(a.events, e)
	a.mu.Unlock()
}

func loadCfg(t *testing.T, js string) *config.Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIPv6HoneypotBansWholeRange(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/.env"],"block_action":"forbidden"`)
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("2400:d321:2277:3897::1", "/.env"))

	rec := httptest.NewRecorder()
	w.ServeHTTP(rec, reqFrom("2400:d321:2277:3897::99", "/"))
	if rec.Code != http.StatusForbidden || hits != 0 {
		t.Fatalf("a rotated address in the same /64 should be blocked (status %d, hits %d)", rec.Code, hits)
	}
	if e, ok := bl.Lookup("2400:d321:2277:3897::1"); !ok || e.IP != "2400:d321:2277:3897::/64" {
		t.Fatalf("ban should be recorded as the /64, got %+v", e)
	}
}

func TestIPv6BanPrefix128BansSingleAddress(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/.env"],"block_action":"forbidden","ipv6_ban_prefix":128`)
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("2400:d321:2277:3897::1", "/.env"))
	if !bl.IsBlocked("2400:d321:2277:3897::1") || bl.IsBlocked("2400:d321:2277:3897::2") {
		t.Fatal("prefix 128 should ban only the single address")
	}
}

func TestWhitelistedIPv6NeverBansItsRange(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits),
		`,"honeypots":["/.env"],"block_action":"forbidden","whitelist":["2400:d321:2277:3897::1"]`)
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("2400:d321:2277:3897::1", "/.env"))
	if bl.Count() != 0 {
		t.Fatalf("a whitelisted client's honeypot hit must not ban its range (entries: %v)", bl.List())
	}
}

func TestTempBanCountsIPv6RangeAsOneClient(t *testing.T) {
	notFound := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
	extra := `,"block_action":"forbidden","temp_ban":{"enabled":true,"max":3,"status_codes":[404]}`
	w, bl := newWAF(t, notFound, extra)
	for i := 1; i <= 3; i++ {
		w.ServeHTTP(httptest.NewRecorder(), reqFrom(fmt.Sprintf("2400:d321:2277:3897::%d", i), "/missing"))
	}
	if !bl.IsBlocked("2400:d321:2277:3897::abcd") {
		t.Fatal("strikes from rotating addresses in one /64 should add up to a range temp-ban")
	}
}

func TestRepeatTempBansEscalateToPermanent(t *testing.T) {
	notFound := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }
	extra := `,"block_action":"forbidden","temp_ban":{"enabled":true,"max":1,"ban_duration":"20ms",
		"status_codes":[404],"escalate_after":2,"escalate_window":"1h"}`
	w, bl := newWAF(t, notFound, extra)

	const ip = "6.6.6.6"
	w.ServeHTTP(httptest.NewRecorder(), reqFrom(ip, "/missing"))
	if e, ok := bl.Lookup(ip); !ok || e.Until.IsZero() {
		t.Fatalf("first offence should be a temp-ban, got %+v", e)
	}
	time.Sleep(40 * time.Millisecond) // let it lapse
	w.ServeHTTP(httptest.NewRecorder(), reqFrom(ip, "/missing"))
	e, ok := bl.Lookup(ip)
	if !ok || !e.Until.IsZero() || e.Reason != "repeat-offender" {
		t.Fatalf("second temp-ban within the window should escalate to permanent, got %+v", e)
	}
	if w.Stats().Snapshot().Escalated != 1 {
		t.Error("escalation should be counted")
	}
}

func TestReloadSwapsHoneypotsAndWhitelist(t *testing.T) {
	var hits int32
	w, bl := newWAF(t, okBackend(&hits), `,"honeypots":["/old"],"block_action":"forbidden"`)
	w.Reload(loadCfg(t, `{"upstream":"10.0.0.1","honeypots":["/new"],"block_action":"forbidden","whitelist":["7.7.7.7"]}`))

	w.ServeHTTP(httptest.NewRecorder(), reqFrom("1.1.1.1", "/old"))
	if bl.IsBlocked("1.1.1.1") {
		t.Fatal("a removed honeypot should no longer ban")
	}
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("2.2.2.2", "/new"))
	if !bl.IsBlocked("2.2.2.2") {
		t.Fatal("a newly added honeypot should ban")
	}
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("7.7.7.7", "/new"))
	if bl.IsBlocked("7.7.7.7") {
		t.Fatal("the reloaded whitelist should apply")
	}
	if hits != 1 {
		t.Fatalf("only the /old request should have been proxied after reload (hits = %d)", hits)
	}
}

func TestEventsCarryCountryAndUAAndReachArchive(t *testing.T) {
	var hits int32
	w, _ := newWAF(t, okBackend(&hits), `,"honeypots":["/.env"],"block_action":"forbidden"`)
	arch := &recordingArchive{}
	w.SetArchive(arch)

	r := reqFrom("8.8.4.4", "/page?"+strings.Repeat("q", 5000))
	r.Header.Set("Cf-Ipcountry", "DE")
	r.Header.Set("User-Agent", "Mozilla/5.0 test")
	w.ServeHTTP(httptest.NewRecorder(), r)
	w.ServeHTTP(httptest.NewRecorder(), reqFrom("8.8.4.4", "/.env"))

	if len(arch.events) != 2 {
		t.Fatalf("archive got %d events, want 2 (proxied + honeypot)", len(arch.events))
	}
	e := arch.events[0]
	if e.Country != "DE" || e.UA != "Mozilla/5.0 test" || e.Outcome != "proxied" {
		t.Errorf("event = %+v", e)
	}
	if len(e.Query) != maxQueryLen {
		t.Errorf("query should be truncated to %d, got %d", maxQueryLen, len(e.Query))
	}
	if arch.events[1].Outcome != "honeypot" {
		t.Errorf("honeypot hit should be archived too: %+v", arch.events[1])
	}
}
