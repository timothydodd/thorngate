package archive

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"thorngate/internal/stats"
)

// fixture writes events spread over the last three hours plus the current one
// and returns the open archive and the current hour's start.
func fixture(t *testing.T) (*Archive, time.Time) {
	t.Helper()
	dir := t.TempDir()
	a, err := Open(dir, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	base := time.Now().UTC().Truncate(time.Hour)
	ev := func(at time.Time, ip, path, outcome string, status int) {
		a.Append(stats.Event{Time: at, IP: ip, Path: path, Outcome: outcome, Status: status, Host: "app.example.com", UA: "ua-" + ip})
	}
	ev(base.Add(-3*time.Hour+time.Minute), "1.1.1.1", "/x", "proxied", 200)
	ev(base.Add(-2*time.Hour+time.Minute), "2.2.2.2", "/.env", "honeypot", 0)
	ev(base.Add(-1*time.Hour+time.Minute), "1.1.1.1", "/y", "proxied", 404)
	ev(base.Add(-1*time.Hour+2*time.Minute), "3.3.3.3", "/x", "blocked", 403)
	ev(base.Add(time.Second), "1.1.1.1", "/z", "proxied", 200)
	a.sync()
	return a, base
}

func TestQueryAcrossSealedAndLiveHours(t *testing.T) {
	a, base := fixture(t)

	segs, err := a.segments(time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	sealed := 0
	for _, s := range segs {
		if s.sealed() {
			sealed++
		}
	}
	if len(segs) != 4 || sealed != 3 {
		t.Fatalf("segments = %d (sealed %d), want 4 with 3 sealed", len(segs), sealed)
	}

	p, err := a.Query(stats.Filter{}, 1, 50)
	if err != nil {
		t.Fatal(err)
	}
	if p.Total != 5 || p.Events[0].Path != "/z" || p.Events[4].Path != "/x" {
		t.Fatalf("all events newest first: total=%d events=%+v", p.Total, p.Events)
	}

	p, _ = a.Query(stats.Filter{IP: "1.1.1.1"}, 2, 2) // page 2 of 3 matches
	if p.Total != 3 || len(p.Events) != 1 || p.Events[0].Path != "/x" {
		t.Fatalf("paged IP query: %+v", p)
	}
	if p.IPCounts["1.1.1.1"] != 3 {
		t.Errorf("ip count = %d, want 3", p.IPCounts["1.1.1.1"])
	}

	for _, tc := range []struct {
		f    stats.Filter
		want int
	}{
		{stats.Filter{IP: "1.1.1.1", Text: "/y"}, 1},
		{stats.Filter{IP: "9.9.9.9"}, 0},
		{stats.Filter{Outcome: "honeypot"}, 1},
		{stats.Filter{Status: "4xx"}, 2},
		{stats.Filter{Text: "UA-3"}, 1},
		{stats.Filter{Since: base.Add(-90 * time.Minute)}, 3},
		{stats.Filter{Since: base.Add(-90 * time.Minute), IP: "1.1.1.1"}, 2},
		{stats.Filter{Until: base.Add(-2 * time.Hour)}, 1},
	} {
		p, err := a.Query(tc.f, 1, 50)
		if err != nil {
			t.Fatal(err)
		}
		if p.Total != tc.want || len(p.Events) != tc.want {
			t.Errorf("%+v: total=%d events=%d, want %d", tc.f, p.Total, len(p.Events), tc.want)
		}
	}
}

func TestTopSummaryHourly(t *testing.T) {
	a, base := fixture(t)
	since := base.Add(-4 * time.Hour)

	top, err := a.Top(since, 10)
	if err != nil {
		t.Fatal(err)
	}
	if top.IPs[0].Key != "1.1.1.1" || top.IPs[0].Count != 3 || top.Paths[0].Key != "/x" || top.Paths[0].Count != 2 {
		t.Errorf("top = %+v", top)
	}

	s, err := a.IPSummary("1.1.1.1", since)
	if err != nil {
		t.Fatal(err)
	}
	if s.Requests != 3 || s.Statuses["2xx"] != 2 || s.Statuses["4xx"] != 1 || s.UA != "ua-1.1.1.1" {
		t.Errorf("summary = %+v", s)
	}
	if s.LastSeen == nil || !s.LastSeen.Equal(base.Add(time.Second)) {
		t.Errorf("last seen = %v", s.LastSeen)
	}

	h, err := a.Hourly(since)
	if err != nil {
		t.Fatal(err)
	}
	var reqs, blocked uint64
	for _, b := range h {
		reqs += b.Requests
		blocked += b.Blocked
	}
	if len(h) != 5 || reqs != 5 || blocked != 2 {
		t.Errorf("hourly: %d buckets, %d requests, %d blocked", len(h), reqs, blocked)
	}
}

func TestOpenSealsLeftoversAndPrunes(t *testing.T) {
	dir := t.TempDir()
	old := hourKey(time.Now().Add(-5 * time.Hour))
	ancient := hourKey(time.Now().Add(-40 * 24 * time.Hour))
	// A leftover plain segment with a torn final line from a crash.
	leftover := `{"time":"` + time.Now().Add(-5*time.Hour).UTC().Format(time.RFC3339) + `","ip":"4.4.4.4","path":"/a","outcome":"proxied"}` + "\n" + `{"time":"20`
	if err := os.WriteFile(filepath.Join(dir, old+extPlain), []byte(leftover), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ancient+extGz), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	a, err := Open(dir, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	for _, name := range []string{old + extGz, old + extIdx} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s should exist after sealing: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, old+extPlain)); !os.IsNotExist(err) {
		t.Error("plain leftover should be removed once sealed")
	}
	if _, err := os.Stat(filepath.Join(dir, ancient+extGz)); !os.IsNotExist(err) {
		t.Error("segment past retention should be pruned")
	}
	p, err := a.Query(stats.Filter{IP: "4.4.4.4"}, 1, 50)
	if err != nil || p.Total != 1 {
		t.Fatalf("sealed leftover should be queryable (torn line skipped): %+v %v", p, err)
	}
}

func TestCloseFlushesAndReopenAppends(t *testing.T) {
	dir := t.TempDir()
	a, err := Open(dir, time.Hour*24)
	if err != nil {
		t.Fatal(err)
	}
	a.Append(stats.Event{Time: time.Now().UTC(), IP: "5.5.5.5", Path: "/one", Outcome: "proxied"})
	a.Close()

	b, err := Open(dir, time.Hour*24)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	b.Append(stats.Event{Time: time.Now().UTC(), IP: "5.5.5.5", Path: "/two", Outcome: "proxied"})
	p, err := b.Query(stats.Filter{IP: "5.5.5.5"}, 1, 50)
	if err != nil || p.Total != 2 {
		t.Fatalf("events from both runs should be kept: %+v %v", p, err)
	}
	if segs, n := b.Usage(); segs != 1 || n == 0 {
		t.Errorf("usage = %d segments, %d bytes", segs, n)
	}
	if !strings.HasPrefix(p.Events[0].Path, "/two") {
		t.Errorf("newest first: %+v", p.Events)
	}
}
