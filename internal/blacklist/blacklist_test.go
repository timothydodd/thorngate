package blacklist

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

func TestConcurrentAddsPersistEverything(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bl.json")
	bl, err := New(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	const n = 300
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bl.Add(fmt.Sprintf("10.0.%d.%d", i/250, i%250), "honeypot", "/x")
		}(i)
	}
	wg.Wait()

	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatalf("concurrent bans corrupted the file: %v", err)
	}
	if len(list) != n {
		t.Fatalf("file holds %d bans, want %d (a stale snapshot overwrote a newer one)", len(list), n)
	}
}

func TestCorruptFileIsMovedAsideNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "bl.json")
	if err := os.WriteFile(file, []byte(`[{"ip":"1.2.3.4"}{"ip":`), 0o644); err != nil {
		t.Fatal(err)
	}
	bl, err := New(file, nil)
	if err != nil {
		t.Fatalf("a corrupt file should not stop startup: %v", err)
	}
	if bl.Count() != 0 {
		t.Fatalf("Count = %d, want 0", bl.Count())
	}
	matches, _ := filepath.Glob(file + ".corrupt-*")
	if len(matches) != 1 {
		t.Fatalf("corrupt file should be set aside, found %v", matches)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("corrupt file should have been moved, not left in place")
	}
}

func TestWhitelistOverridesExistingExactBan(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bl.json")
	bl1, err := New(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	bl1.Add("1.2.3.4", "manual", "")

	// Restart with the IP now whitelisted in config.
	bl2, err := New(file, []string{"1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if bl2.IsBlocked("1.2.3.4") {
		t.Fatal("a whitelisted IP must not be blocked by a ban made before it was whitelisted")
	}
}

func TestKeysAreNormalized(t *testing.T) {
	bl := newBL(t, nil)
	bl.Add("2001:DB8:0::1", "manual", "")
	if !bl.IsBlocked("2001:db8::1") {
		t.Fatal("IPv6 ban should match regardless of case / zero compression")
	}
	bl.Add("::ffff:9.9.9.9", "manual", "")
	if !bl.IsBlocked("9.9.9.9") {
		t.Fatal("IPv4-mapped IPv6 ban should match the plain IPv4 address")
	}
	if !bl.Remove("2001:0db8::0001") {
		t.Fatal("Remove should accept any spelling of the address")
	}
	bl.Add("1.2.3.4/24", "manual", "")
	for _, e := range bl.List() {
		if strings.Contains(e.IP, "/") && e.IP != "1.2.3.0/24" {
			t.Fatalf("CIDR stored as %q, want normalized 1.2.3.0/24", e.IP)
		}
	}
}

func TestSweepDropsExpiredBans(t *testing.T) {
	file := filepath.Join(t.TempDir(), "bl.json")
	bl, err := New(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	bl.AddTemp("5.5.5.5", "rate-limit", 10*time.Millisecond)
	bl.Add("6.6.6.6", "honeypot", "/x")
	time.Sleep(30 * time.Millisecond)

	if got := len(bl.List()); got != 1 {
		t.Fatalf("List should hide expired bans, got %d entries", got)
	}
	if n := bl.Sweep(); n != 1 {
		t.Fatalf("Sweep dropped %d, want 1", n)
	}
	if bl.Count() != 1 {
		t.Fatalf("Count after sweep = %d, want 1", bl.Count())
	}
	reloaded, err := New(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Count() != 1 || !reloaded.IsBlocked("6.6.6.6") {
		t.Fatal("sweep result should be persisted with the permanent ban intact")
	}
}

func TestExpiredExactBanStillCoveredByCIDR(t *testing.T) {
	bl := newBL(t, nil)
	bl.Add("7.7.7.0/24", "manual", "")
	bl.AddTemp("7.7.7.7", "rate-limit", 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if !bl.IsBlocked("7.7.7.7") {
		t.Fatal("an expired exact ban must not hide a covering CIDR ban")
	}
}
