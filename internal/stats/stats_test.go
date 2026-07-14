package stats

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCountersAndStatusClasses(t *testing.T) {
	c := New(60, 100)
	c.Request(false)
	c.Request(false)
	c.Request(true) // blocked
	c.Honeypot()
	c.TempBan()
	c.TempBan()

	for _, code := range []int{200, 204, 301, 404, 403, 500, 502} {
		c.Status(code)
	}

	s := c.Snapshot()
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"requests", s.Requests, 3},
		{"blocked", s.Blocked, 1},
		{"honeypots", s.Honeypots, 1},
		{"temp_bans", s.TempBans, 2},
		{"2xx", s.Status2xx, 2},
		{"3xx", s.Status3xx, 1},
		{"4xx", s.Status4xx, 2},
		{"5xx", s.Status5xx, 2},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
		}
	}
}

func TestWindowDefaultsAndSeriesLength(t *testing.T) {
	for _, win := range []int{0, -5, 30} {
		c := New(win, 100)
		want := win
		if win <= 0 {
			want = 60
		}
		if got := len(c.Snapshot().Series); got != want {
			t.Errorf("New(%d): series length = %d, want %d", win, got, want)
		}
	}
}

func TestSeriesAggregatesCurrentMinute(t *testing.T) {
	c := New(60, 100)
	c.Request(false)
	c.Request(true)
	c.Request(false)

	series := c.Snapshot().Series
	last := series[len(series)-1] // current minute is always the newest bucket
	if last.Requests != 3 {
		t.Errorf("current-minute requests = %d, want 3", last.Requests)
	}
	if last.Blocked != 1 {
		t.Errorf("current-minute blocked = %d, want 1", last.Blocked)
	}

	// All other buckets in a freshly-created collector should be empty.
	var other uint64
	for _, b := range series[:len(series)-1] {
		other += b.Requests
	}
	if other != 0 {
		t.Errorf("non-current buckets had %d requests, want 0", other)
	}
}

func TestRecentFeedNewestFirstAndBounded(t *testing.T) {
	c := New(60, 3) // tiny ring to exercise wraparound
	for _, p := range []string{"/a", "/b", "/c", "/d", "/e"} {
		c.Observe(Event{Time: time.Now().UTC(), IP: "1.1.1.1", Path: p, Status: 200, Outcome: "proxied"})
	}

	page := c.Recent(0, 1, 10)
	if page.Total != 3 {
		t.Fatalf("total = %d, want 3 (bounded to capacity)", page.Total)
	}
	// Newest first, oldest two ("/a", "/b") evicted.
	want := []string{"/e", "/d", "/c"}
	for i, w := range want {
		if page.Events[i].Path != w {
			t.Errorf("events[%d].Path = %q, want %q", i, page.Events[i].Path, w)
		}
	}
}

func TestRecentFeedDisabled(t *testing.T) {
	c := New(60, -1) // negative clamps to 0 → feed off
	c.Observe(Event{IP: "1.1.1.1", Path: "/x"})
	if got := c.Recent(0, 1, 10).Total; got != 0 {
		t.Errorf("total = %d, want 0 when feed disabled", got)
	}
}

func TestRecentPaginationAndIPCounts(t *testing.T) {
	c := New(60, 100)
	now := time.Now().UTC()
	// 7 requests from a chatty IP, 2 from a quiet one, interleaved.
	for i := 0; i < 7; i++ {
		c.Observe(Event{Time: now, IP: "9.9.9.9", Path: "/scan", Status: 404, Outcome: "proxied"})
	}
	c.Observe(Event{Time: now, IP: "1.1.1.1", Path: "/ok", Status: 200, Outcome: "proxied"})
	c.Observe(Event{Time: now, IP: "1.1.1.1", Path: "/ok2", Status: 200, Outcome: "proxied"})

	page := c.Recent(24*time.Hour, 1, 4)
	if page.Total != 9 {
		t.Fatalf("total = %d, want 9", page.Total)
	}
	if len(page.Events) != 4 {
		t.Fatalf("page 1 length = %d, want 4", len(page.Events))
	}
	// Counts are window-wide even though the page only shows a slice.
	if got := page.IPCounts["1.1.1.1"]; got != 2 {
		t.Errorf("ip_counts[1.1.1.1] = %d, want 2", got)
	}

	page3 := c.Recent(24*time.Hour, 3, 4)
	if page3.Page != 3 || len(page3.Events) != 1 {
		t.Errorf("page 3: page=%d len=%d, want page=3 len=1", page3.Page, len(page3.Events))
	}
	if got := page3.IPCounts["9.9.9.9"]; got != 7 {
		t.Errorf("ip_counts[9.9.9.9] = %d, want 7", got)
	}

	// Out-of-range page clamps to the last page.
	if got := c.Recent(24*time.Hour, 99, 4).Page; got != 3 {
		t.Errorf("page clamp = %d, want 3", got)
	}
}

func TestRecentAgeWindow(t *testing.T) {
	c := New(60, 100)
	now := time.Now().UTC()
	c.Observe(Event{Time: now.Add(-25 * time.Hour), IP: "1.1.1.1", Path: "/old"})
	c.Observe(Event{Time: now, IP: "1.1.1.1", Path: "/new"})

	page := c.Recent(24*time.Hour, 1, 10)
	if page.Total != 1 || page.Events[0].Path != "/new" {
		t.Errorf("got total=%d, want only /new inside the 24h window", page.Total)
	}
}

func TestBytesSent(t *testing.T) {
	c := New(60, 100)
	c.Bytes(1500)
	c.Bytes(500)
	c.Bytes(-3) // ignored
	if got := c.Snapshot().BytesSent; got != 2000 {
		t.Errorf("bytes_sent = %d, want 2000", got)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	file := filepath.Join(t.TempDir(), "stats.json")
	now := time.Now().UTC()

	c1 := New(60, 100)
	c1.Request(false)
	c1.Request(true)
	c1.Honeypot()
	c1.Status(200)
	c1.Status(404)
	c1.Bytes(1234)
	c1.Observe(Event{Time: now, IP: "1.1.1.1", Path: "/a", Status: 200, Outcome: "proxied"})
	c1.Observe(Event{Time: now, IP: "2.2.2.2", Path: "/b", Status: 403, Outcome: "blocked"})
	if err := c1.Save(file); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2 := New(60, 100)
	if err := c2.Load(file); err != nil {
		t.Fatalf("load: %v", err)
	}

	s1, s2 := c1.Snapshot(), c2.Snapshot()
	if s2.Requests != s1.Requests || s2.Blocked != s1.Blocked || s2.Honeypots != s1.Honeypots ||
		s2.Status2xx != s1.Status2xx || s2.Status4xx != s1.Status4xx || s2.BytesSent != s1.BytesSent {
		t.Errorf("counters differ after reload: got %+v, want %+v", s2, s1)
	}
	if !s2.Since.Equal(s1.Since) {
		t.Errorf("since = %v, want %v", s2.Since, s1.Since)
	}

	// The traffic series should survive the reload (summed, in case the minute
	// rolled over between save and load).
	var reqs, blk uint64
	for _, b := range s2.Series {
		reqs += b.Requests
		blk += b.Blocked
	}
	if reqs != 2 || blk != 1 {
		t.Errorf("series after reload: requests=%d blocked=%d, want 2/1", reqs, blk)
	}

	// The recent feed should come back newest-first with counts intact.
	page := c2.Recent(0, 1, 10)
	if page.Total != 2 {
		t.Fatalf("recent total = %d, want 2", page.Total)
	}
	if page.Events[0].Path != "/b" || page.Events[1].Path != "/a" {
		t.Errorf("recent order = %q,%q, want /b,/a", page.Events[0].Path, page.Events[1].Path)
	}

	// New events after a reload keep the ring consistent.
	c2.Observe(Event{Time: now, IP: "3.3.3.3", Path: "/c", Status: 200, Outcome: "proxied"})
	if got := c2.Recent(0, 1, 10).Events[0].Path; got != "/c" {
		t.Errorf("newest after reload = %q, want /c", got)
	}
}

func TestLoadShrunkRecentCapacityKeepsNewest(t *testing.T) {
	file := filepath.Join(t.TempDir(), "stats.json")
	now := time.Now().UTC()

	c1 := New(60, 10)
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		c1.Observe(Event{Time: now, IP: "1.1.1.1", Path: p})
	}
	if err := c1.Save(file); err != nil {
		t.Fatalf("save: %v", err)
	}

	c2 := New(60, 2) // feed shrunk between runs
	if err := c2.Load(file); err != nil {
		t.Fatalf("load: %v", err)
	}
	page := c2.Recent(0, 1, 10)
	if page.Total != 2 || page.Events[0].Path != "/d" || page.Events[1].Path != "/c" {
		t.Errorf("shrunk feed = %+v, want newest two /d,/c", page.Events)
	}
}

func TestLoadMissingFileIsNoop(t *testing.T) {
	c := New(60, 10)
	if err := c.Load(filepath.Join(t.TempDir(), "nope.json")); err != nil {
		t.Errorf("missing file should not error: %v", err)
	}
}

func TestLoadCorruptFileErrors(t *testing.T) {
	file := filepath.Join(t.TempDir(), "stats.json")
	if err := os.WriteFile(file, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New(60, 10).Load(file); err == nil {
		t.Error("corrupt file should error")
	}
}
