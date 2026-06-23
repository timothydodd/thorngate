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

	recent := c.Snapshot().Recent
	if len(recent) != 3 {
		t.Fatalf("recent length = %d, want 3 (bounded to capacity)", len(recent))
	}
	// Newest first, oldest two ("/a", "/b") evicted.
	want := []string{"/e", "/d", "/c"}
	for i, w := range want {
		if recent[i].Path != w {
			t.Errorf("recent[%d].Path = %q, want %q", i, recent[i].Path, w)
		}
	}
}

func TestRecentFeedDisabled(t *testing.T) {
	c := New(60, -1) // negative clamps to 0 → feed off
	c.Observe(Event{IP: "1.1.1.1", Path: "/x"})
	if got := len(c.Snapshot().Recent); got != 0 {
		t.Errorf("recent length = %d, want 0 when feed disabled", got)
	}
}
