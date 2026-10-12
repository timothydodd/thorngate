package activity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNilLogIsNoop(t *testing.T) {
	var l *Log
	l.Addf(Ban, Info, "1.2.3.4", "x", "hello")
	l.Close()
	if ev, n := l.List(Query{}); len(ev) != 0 || n != 0 {
		t.Fatal("nil log should list nothing")
	}
}

func TestListFiltersAndPages(t *testing.T) {
	l, err := New(100, "")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		l.Addf(Ban, Info, "192.0.2.1", "honeypot", "ban %d", i)
	}
	l.Addf(Auth, Warn, "10.0.0.1", "admin", "Failed login")

	ev, total := l.List(Query{})
	if total != 11 || ev[0].Message != "Failed login" {
		t.Fatalf("total=%d first=%q, want 11 newest first", total, ev[0].Message)
	}
	if _, n := l.List(Query{Category: Ban}); n != 10 {
		t.Errorf("ban category = %d, want 10", n)
	}
	if _, n := l.List(Query{Level: Warn}); n != 1 {
		t.Errorf("warn level = %d, want 1", n)
	}
	if _, n := l.List(Query{Search: "ADMIN"}); n != 1 {
		t.Errorf("search on actor = %d, want 1", n)
	}
	ev, total = l.List(Query{Category: Ban, Offset: 2, Limit: 3})
	if total != 10 || len(ev) != 3 || ev[0].Message != "ban 7" {
		t.Errorf("page = %d events from %q (total %d), want 3 from \"ban 7\"", len(ev), ev[0].Message, total)
	}
}

func TestBounded(t *testing.T) {
	l, _ := New(10, "")
	for i := 0; i < 100; i++ {
		l.Addf(System, Info, "", "", "e%d", i)
	}
	ev, total := l.List(Query{})
	if total != 10 || ev[0].Message != "e99" || ev[9].Message != "e90" {
		t.Errorf("total=%d range %q..%q, want the last 10", total, ev[0].Message, ev[len(ev)-1].Message)
	}
}

func TestPersistsAndCompacts(t *testing.T) {
	file := filepath.Join(t.TempDir(), "activity.jsonl")
	l, err := New(5, file)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 23; i++ {
		l.Addf(System, Info, "", "", "e%d", i)
	}
	l.Close()

	data, _ := os.ReadFile(file)
	if n := strings.Count(string(data), "\n"); n > 10 {
		t.Errorf("file holds %d lines, want it compacted to at most 2x max", n)
	}

	l2, err := New(5, file)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	ev, total := l2.List(Query{})
	if total != 5 || ev[0].Message != "e22" {
		t.Errorf("reloaded total=%d newest=%q, want 5 ending at e22", total, ev[0].Message)
	}
	l2.Addf(System, Info, "", "", "after restart")
	if ev, _ := l2.List(Query{Limit: 1}); ev[0].Message != "after restart" {
		t.Error("appending after reload should work")
	}
}
