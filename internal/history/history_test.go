package history

import (
	"testing"
	"time"
)

func rec(path string) Record {
	return Record{Time: time.Now().UTC(), Method: "GET", Path: path, Status: 200}
}

func TestKeepsLastDepthRequestsOldestFirst(t *testing.T) {
	tr := New(3, 16, time.Minute)
	for _, p := range []string{"/a", "/b", "/c", "/d"} {
		tr.Record("1.1.1.1", rec(p))
	}
	got := tr.History("1.1.1.1")
	if len(got) != 3 {
		t.Fatalf("want 3 records (depth), got %d", len(got))
	}
	want := []string{"/b", "/c", "/d"} // oldest dropped, oldest-first order
	for i, w := range want {
		if got[i].Path != w {
			t.Fatalf("record %d: want %s, got %s", i, w, got[i].Path)
		}
	}
}

func TestHistoryIsPerIP(t *testing.T) {
	tr := New(5, 16, time.Minute)
	tr.Record("1.1.1.1", rec("/a"))
	if h := tr.History("2.2.2.2"); h != nil {
		t.Fatalf("unknown IP must have no history, got %v", h)
	}
}

func TestForgetClearsHistory(t *testing.T) {
	tr := New(5, 16, time.Minute)
	tr.Record("1.1.1.1", rec("/a"))
	tr.Forget("1.1.1.1")
	if h := tr.History("1.1.1.1"); h != nil {
		t.Fatalf("history should be gone after Forget, got %v", h)
	}
}

func TestEvictsOldestIPPastMaxIPs(t *testing.T) {
	tr := New(5, 2, time.Minute)
	tr.Record("1.1.1.1", Record{Time: time.Now().Add(-2 * time.Minute), Path: "/old"})
	tr.Record("2.2.2.2", Record{Time: time.Now().Add(-1 * time.Minute), Path: "/mid"})
	tr.Record("3.3.3.3", Record{Time: time.Now(), Path: "/new"}) // forces eviction

	if h := tr.History("1.1.1.1"); h != nil {
		t.Fatalf("least-recently-active IP should have been evicted, got %v", h)
	}
	if h := tr.History("3.3.3.3"); len(h) != 1 {
		t.Fatalf("newest IP should be tracked, got %v", h)
	}
}

func TestSweepDropsIdleIPs(t *testing.T) {
	tr := New(5, 16, 20*time.Millisecond)
	tr.Record("1.1.1.1", rec("/a"))
	time.Sleep(40 * time.Millisecond)
	tr.Sweep()
	if h := tr.History("1.1.1.1"); h != nil {
		t.Fatalf("idle IP should be swept, got %v", h)
	}
}
