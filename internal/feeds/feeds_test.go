package feeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"thorngate/internal/blacklist"
	"thorngate/internal/config"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "openai/google json",
			body: `{"creationTime":"2026-01-02T11:00:00","prefixes":[
				{"ipv4Prefix":"104.210.140.128/28"},
				{"ipv6Prefix":"2001:DB8::/48"},
				{"ipv4Prefix":"13.66.216.180/28"},
				{"ipv4Prefix":"104.210.140.128/28"}]}`,
			want: []string{"104.210.140.128/28", "13.66.216.176/28", "2001:db8::/48"},
		},
		{
			name: "plain text",
			body: "# crawler ranges\n192.0.2.0/24\n\n198.51.100.7  # one host\nnot-an-ip\n",
			want: []string{"192.0.2.0/24", "198.51.100.7"},
		},
		{
			name: "too broad ranges dropped",
			body: "0.0.0.0/0\n::/0\n10.0.0.0/7\n10.0.0.0/8\n",
			want: []string{"10.0.0.0/8"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.body))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}

	for _, bad := range []string{``, `{"prefixes":[]}`, `{"prefixes":`, "garbage\n", "0.0.0.0/0"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("Parse(%q) should fail", bad)
		}
	}
}

// fakeStore records the groups set on it and unbans nothing.
type fakeStore struct {
	mu     sync.Mutex
	groups map[string][]string
}

func (f *fakeStore) SetWhitelistGroup(name string, specs []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(specs) == 0 {
		delete(f.groups, name)
		return
	}
	f.groups[name] = specs
}

func (f *fakeStore) RemoveCovered([]string) []blacklist.Entry { return nil }

func TestRefreshAddsRemovesAndKeepsLastGood(t *testing.T) {
	body := `{"prefixes":[{"ipv4Prefix":"192.0.2.0/28"},{"ipv4Prefix":"192.0.2.32/28"}]}`
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	store := &fakeStore{groups: map[string][]string{}}
	m := New(store)
	// Register the feed without its poller so refreshes are driven by the test.
	ctx := context.Background()
	m.feeds[srv.URL] = &feed{cancel: func() {}}
	m.status[srv.URL] = &Status{URL: srv.URL}

	if err := m.refresh(ctx, srv.URL); err != nil {
		t.Fatal(err)
	}
	if got := store.groups[srv.URL]; !reflect.DeepEqual(got, []string{"192.0.2.0/28", "192.0.2.32/28"}) {
		t.Fatalf("group = %v", got)
	}

	// The feed drops a range and adds one: the group follows it exactly.
	body = `{"prefixes":[{"ipv4Prefix":"192.0.2.32/28"},{"ipv4Prefix":"198.51.100.0/24"}]}`
	if err := m.refresh(ctx, srv.URL); err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.32/28", "198.51.100.0/24"}
	if got := store.groups[srv.URL]; !reflect.DeepEqual(got, want) {
		t.Fatalf("group after refresh = %v, want %v", got, want)
	}

	// Failures (HTTP error, empty list) keep the last good list.
	status = http.StatusInternalServerError
	if err := m.refresh(ctx, srv.URL); err == nil {
		t.Error("HTTP 500 should fail")
	}
	status, body = http.StatusOK, `{"prefixes":[]}`
	if err := m.refresh(ctx, srv.URL); err == nil {
		t.Error("an empty feed should fail")
	}
	if got := store.groups[srv.URL]; !reflect.DeepEqual(got, want) {
		t.Errorf("group after failures = %v, want last good %v", got, want)
	}
	if st := m.Statuses()[0]; st.Error == "" || !reflect.DeepEqual(st.Prefixes, want) {
		t.Errorf("status = %+v, want an error and the last good prefixes", st)
	}
}

func TestApplyRemovesDroppedFeedGroup(t *testing.T) {
	store := &fakeStore{groups: map[string][]string{"https://gone.example/x": {"192.0.2.0/24"}}}
	m := New(store)
	m.feeds["https://gone.example/x"] = &feed{cancel: func() {}}
	m.status["https://gone.example/x"] = &Status{URL: "https://gone.example/x"}

	m.Apply([]config.WhitelistFeed{})
	if _, ok := store.groups["https://gone.example/x"]; ok {
		t.Error("a feed removed from the config should have its group dropped")
	}
	if len(m.Statuses()) != 0 {
		t.Error("a removed feed should leave no status")
	}
}

func TestRefreshUnbansCoveredEntries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("192.0.2.0/28\n"))
	}))
	defer srv.Close()

	bl, err := blacklist.New("", nil)
	if err != nil {
		t.Fatal(err)
	}
	bl.Add("192.0.2.5", "honeypot", "/wp-admin")
	bl.Add("203.0.113.1", "honeypot", "/.env")

	m := New(bl)
	m.feeds[srv.URL] = &feed{cancel: func() {}}
	m.status[srv.URL] = &Status{URL: srv.URL}
	if err := m.refresh(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	if !bl.IsWhitelisted("192.0.2.9") {
		t.Error("feed range should be whitelisted")
	}
	if bl.Count() != 1 || bl.IsBlocked("203.0.113.1") == false {
		t.Errorf("only the ban inside the feed range should be lifted (count=%d)", bl.Count())
	}
}
