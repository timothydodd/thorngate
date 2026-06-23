package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thorngate/internal/blacklist"
	"thorngate/internal/stats"
)

const token = "secret-token"

func newServer(t *testing.T) (*httptest.Server, *blacklist.Blacklist) {
	t.Helper()
	bl, err := blacklist.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(Handler(bl, stats.New(60, 100), token)), bl
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

	if res := do(t, srv, "GET", "/admin/", "", ""); res.StatusCode != http.StatusOK {
		t.Errorf("page: got %d, want 200", res.StatusCode)
	}
}
