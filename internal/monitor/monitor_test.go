package monitor

import (
	"testing"
	"time"
)

func TestStrikeTriggersAtThreshold(t *testing.T) {
	m := New(3, time.Minute)
	if m.Strike("1.1.1.1") {
		t.Fatal("strike 1 should not trigger")
	}
	if m.Strike("1.1.1.1") {
		t.Fatal("strike 2 should not trigger")
	}
	if !m.Strike("1.1.1.1") {
		t.Fatal("strike 3 should trigger")
	}
	// Counter resets after triggering.
	if m.Strike("1.1.1.1") {
		t.Fatal("strike after trigger should start a fresh count")
	}
}

func TestStrikeIsPerIP(t *testing.T) {
	m := New(2, time.Minute)
	m.Strike("1.1.1.1")
	if m.Strike("2.2.2.2") {
		t.Fatal("a different IP must not inherit another IP's strikes")
	}
}

func TestStrikeWindowExpiry(t *testing.T) {
	m := New(2, 20*time.Millisecond)
	m.Strike("1.1.1.1")
	time.Sleep(40 * time.Millisecond)
	// First strike has aged out of the window, so this is only #1 again.
	if m.Strike("1.1.1.1") {
		t.Fatal("strikes outside the window should not count")
	}
}
