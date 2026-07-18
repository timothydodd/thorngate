package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"thorngate/internal/blacklist"
	"thorngate/internal/config"
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
