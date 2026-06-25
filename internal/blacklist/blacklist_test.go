package blacklist

import (
	"path/filepath"
	"testing"
	"time"
)

func newBL(t *testing.T, whitelist []string) *Blacklist {
	t.Helper()
	bl, err := New("", whitelist)
	if err != nil {
		t.Fatal(err)
	}
	return bl
}

func TestAddAndIsBlocked(t *testing.T) {
	bl := newBL(t, nil)
	if !bl.Add("1.2.3.4", "honeypot", "/wp-admin") {
		t.Fatal("Add should report a newly blocked IP")
	}
	if !bl.IsBlocked("1.2.3.4") {
		t.Fatal("IP should be blocked after Add")
	}
	if bl.IsBlocked("1.2.3.5") {
		t.Fatal("unrelated IP must not be blocked")
	}
	if bl.Add("1.2.3.4", "honeypot", "/wp-admin") {
		t.Fatal("re-adding an already-permanent IP should report false")
	}
	if bl.Count() != 1 {
		t.Fatalf("Count = %d, want 1", bl.Count())
	}
}

func TestRemove(t *testing.T) {
	bl := newBL(t, nil)
	bl.Add("1.2.3.4", "honeypot", "")
	if !bl.Remove("1.2.3.4") {
		t.Fatal("Remove should report the IP was present")
	}
	if bl.IsBlocked("1.2.3.4") {
		t.Fatal("IP should be unblocked after Remove")
	}
	if bl.Remove("1.2.3.4") {
		t.Fatal("removing an absent IP should report false")
	}
}

func TestWildcardWhitelist(t *testing.T) {
	// "107.214.211.*" should behave like "107.214.211.0/24".
	bl := newBL(t, []string{" 107.214.211.* ", "107.215.*"})
	cases := []struct {
		ip   string
		want bool
	}{
		{"107.214.211.0", true},
		{"107.214.211.45", true},
		{"107.214.211.255", true},
		{"107.214.212.1", false}, // next /24, not covered
		{"107.215.9.9", true},    // /16 wildcard
		{"107.216.0.1", false},
	}
	for _, c := range cases {
		if got := bl.IsWhitelisted(c.ip); got != c.want {
			t.Errorf("IsWhitelisted(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestWildcardToCIDR(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"107.214.211.*", "107.214.211.0/24", true},
		{"107.214.*", "107.214.0.0/16", true},
		{"107.*", "107.0.0.0/8", true},
		{"107.214.211.0/24", "", false}, // already CIDR, not a wildcard
		{"1.2.3.4", "", false},          // no wildcard
		{"*", "", false},                // all wild — rejected
		{"*.2.3.4", "", false},          // leading wildcard — rejected
		{"1.*.3.4", "", false},          // literal after wildcard — rejected
	}
	for _, c := range cases {
		got, ok := wildcardToCIDR(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("wildcardToCIDR(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestWhitelistPreventsAdd(t *testing.T) {
	bl := newBL(t, []string{"9.9.9.9", "10.0.0.0/8"})
	if bl.Add("9.9.9.9", "honeypot", "") {
		t.Fatal("whitelisted IP must not be added")
	}
	if bl.IsBlocked("9.9.9.9") {
		t.Fatal("whitelisted IP must never be blocked")
	}
	if bl.Add("10.1.2.3", "honeypot", "") {
		t.Fatal("IP inside a whitelisted CIDR must not be added")
	}
	if bl.IsBlocked("10.1.2.3") {
		t.Fatal("IP inside a whitelisted CIDR must never be blocked")
	}
}

func TestTempBanExpires(t *testing.T) {
	bl := newBL(t, nil)
	if !bl.AddTemp("5.5.5.5", "rate-limit", 20*time.Millisecond) {
		t.Fatal("AddTemp should report a new temporary ban")
	}
	if !bl.IsBlocked("5.5.5.5") {
		t.Fatal("IP should be blocked while the temp ban is active")
	}
	time.Sleep(40 * time.Millisecond)
	if bl.IsBlocked("5.5.5.5") {
		t.Fatal("temp ban should have expired")
	}
}

func TestPermanentOutranksTemp(t *testing.T) {
	bl := newBL(t, nil)
	bl.Add("1.2.3.4", "honeypot", "")
	if bl.AddTemp("1.2.3.4", "rate-limit", time.Hour) {
		t.Fatal("a temp ban must not override an existing permanent ban")
	}
}

func TestUpgradeTempToPermanent(t *testing.T) {
	bl := newBL(t, nil)
	bl.AddTemp("1.2.3.4", "rate-limit", 20*time.Millisecond)
	if !bl.Add("1.2.3.4", "honeypot", "") {
		t.Fatal("upgrading a temp ban to permanent should report true")
	}
	time.Sleep(40 * time.Millisecond)
	if !bl.IsBlocked("1.2.3.4") {
		t.Fatal("a permanent ban must not expire")
	}
}

func TestCIDRBlocksContainedIPs(t *testing.T) {
	bl := newBL(t, nil)
	if !bl.Add("1.2.3.0/24", "honeypot", "") {
		t.Fatal("Add should report a newly blocked CIDR")
	}
	for _, ip := range []string{"1.2.3.1", "1.2.3.254"} {
		if !bl.IsBlocked(ip) {
			t.Fatalf("%s should be blocked by 1.2.3.0/24", ip)
		}
	}
	if bl.IsBlocked("1.2.4.1") {
		t.Fatal("an IP outside the CIDR must not be blocked")
	}
	if bl.Count() != 1 {
		t.Fatalf("Count = %d, want 1", bl.Count())
	}
}

func TestCIDRRespectsWhitelist(t *testing.T) {
	bl := newBL(t, []string{"1.2.3.4"})
	bl.Add("1.2.3.0/24", "honeypot", "")
	if bl.IsBlocked("1.2.3.4") {
		t.Fatal("a whitelisted IP must not be blocked even inside a banned CIDR")
	}
	if !bl.IsBlocked("1.2.3.5") {
		t.Fatal("a non-whitelisted IP in the banned CIDR should be blocked")
	}
}

func TestCIDRRemove(t *testing.T) {
	bl := newBL(t, nil)
	bl.Add("1.2.3.4/24", "honeypot", "") // unnormalized input
	// Removable by the original string...
	if !bl.Remove("1.2.3.4/24") {
		t.Fatal("CIDR should be removable by its original form")
	}
	if bl.IsBlocked("1.2.3.5") {
		t.Fatal("CIDR ban should be gone after Remove")
	}
	// ...and by the normalized network.
	bl.Add("1.2.3.4/24", "honeypot", "")
	if !bl.Remove("1.2.3.0/24") {
		t.Fatal("CIDR should be removable by its normalized form")
	}
	if bl.IsBlocked("1.2.3.5") {
		t.Fatal("CIDR ban should be gone after normalized Remove")
	}
}

func TestPersistAndReload(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bl.json")

	bl1, err := New(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	bl1.Add("1.2.3.4", "honeypot", "/wp-admin")
	bl1.Add("9.9.9.0/24", "honeypot", "")
	// An active temp ban survives a reload; one that lapses while we are down
	// must be dropped.
	bl1.AddTemp("5.5.5.5", "rate-limit", time.Hour)
	bl1.AddTemp("6.6.6.6", "rate-limit", 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)

	bl2, err := New(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bl2.IsBlocked("1.2.3.4") {
		t.Fatal("permanent IP ban should survive a reload")
	}
	if !bl2.IsBlocked("9.9.9.7") {
		t.Fatal("CIDR ban should survive a reload")
	}
	if !bl2.IsBlocked("5.5.5.5") {
		t.Fatal("active temp ban should survive a reload")
	}
	if bl2.IsBlocked("6.6.6.6") {
		t.Fatal("a temp ban that lapsed while down must be dropped on reload")
	}
}
