package stats

import (
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
