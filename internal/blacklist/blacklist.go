package blacklist

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entry records why and when an IP was blacklisted. A zero Until means the ban
// is permanent (e.g. a honeypot hit); a non-zero Until is a temporary ban that
// expires at that time.
type Entry struct {
	IP        string    `json:"ip"`
	Reason    string    `json:"reason"`
	Path      string    `json:"path,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Until     time.Time `json:"until,omitempty"`
}

// MarshalJSON omits a zero Until: omitempty never applies to a struct like
// time.Time, so permanent bans would otherwise carry "0001-01-01T00:00:00Z".
func (e Entry) MarshalJSON() ([]byte, error) {
	type raw Entry // no MarshalJSON method, so no recursion
	out := struct {
		raw
		Until *time.Time `json:"until,omitempty"` // shadows raw.Until
	}{raw: raw(e)}
	if !e.Until.IsZero() {
		out.Until = &e.Until
	}
	return json.Marshal(out)
}

func (e Entry) expired() bool {
	return !e.Until.IsZero() && time.Now().After(e.Until)
}

// maskShape identifies a CIDR prefix length within an address family.
type maskShape struct{ ones, bits int }

// Blacklist is a thread-safe set of blocked IPs with optional file persistence.
// Exact IPs are stored in a hash map for O(1) lookup. CIDR ranges are grouped by
// prefix length, each group keyed by normalized network ("1.2.3.0/24"), so a
// lookup costs one map probe per distinct prefix length in use rather than a
// walk over every banned range — which matters once IPv6 /64 bans pile up.
type Blacklist struct {
	mu      sync.RWMutex
	entries map[string]Entry
	cidrs   map[maskShape]map[string]Entry
	file    string

	// whitelist holds parsed CIDRs / single IPs that are never blocked. It is
	// swapped atomically on config reload, so it is read without the lock.
	whitelist atomic.Pointer[[]*net.IPNet]

	gen       uint64     // bumped on every mutation (guarded by mu)
	persistMu sync.Mutex // serializes disk writes
	savedGen  uint64     // generation last written to disk (guarded by persistMu)
}

// isCIDR reports whether a ban key denotes a CIDR range rather than a single IP.
func isCIDR(key string) bool { return strings.Contains(key, "/") }

// ParseNets turns a list of address specs into matchable networks. Each spec may
// be a single IP ("1.2.3.4"), a CIDR ("10.0.0.0/8"), or an octet wildcard
// ("107.214.211.*" == "107.214.211.0/24", "107.214.*" == "107.214.0.0/16").
// Surrounding whitespace is tolerated; unparseable specs are skipped.
func ParseNets(specs []string) []*net.IPNet {
	var nets []*net.IPNet
	for _, s := range specs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if c, ok := wildcardToCIDR(s); ok {
			s = c
		} else if !strings.Contains(s, "/") {
			// Treat a bare address as a single host.
			if strings.Contains(s, ":") {
				s += "/128" // IPv6
			} else {
				s += "/32" // IPv4
			}
		}
		if _, ipnet, err := net.ParseCIDR(s); err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}

// wildcardToCIDR converts an IPv4 octet-wildcard spec into a CIDR string. The
// wildcard octets must be trailing and contiguous: "107.214.211.*" -> 24 bits,
// "107.214.*" -> 16 bits. Returns ok=false for non-wildcard or malformed specs
// (a leading "*", a "*" before a literal octet, or all octets wild).
func wildcardToCIDR(s string) (string, bool) {
	if !strings.Contains(s, "*") {
		return "", false
	}
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return "", false
	}
	known, seenStar := 0, false
	for _, p := range parts {
		if p == "*" {
			seenStar = true
			continue
		}
		if seenStar {
			return "", false // a literal octet after a wildcard is invalid
		}
		known++
	}
	if known == 0 || known > 3 {
		return "", false
	}
	octets := make([]string, 4)
	for i := 0; i < 4; i++ {
		if i < known {
			octets[i] = parts[i]
		} else {
			octets[i] = "0"
		}
	}
	return strings.Join(octets, ".") + "/" + strconv.Itoa(known*8), true
}

// Matches reports whether ip falls within any of the given networks. It is a
// free function so callers (e.g. the proxy's no-log set) can reuse ParseNets
// without a Blacklist instance.
func Matches(nets []*net.IPNet, ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return containsIP(nets, parsed)
}

// containsIP is Matches for an already-parsed address.
func containsIP(nets []*net.IPNet, parsed net.IP) bool {
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// NormalizeKey canonicalizes a ban key so one address always maps to one entry:
// "2001:DB8::1" -> "2001:db8::1", "::ffff:1.2.3.4" -> "1.2.3.4", and
// "1.2.3.4/24" -> "1.2.3.0/24". Unparseable keys are only trimmed.
func NormalizeKey(key string) string {
	key = strings.TrimSpace(key)
	if isCIDR(key) {
		if _, ipnet, err := net.ParseCIDR(key); err == nil {
			return ipnet.String()
		}
		return key
	}
	if ip := net.ParseIP(key); ip != nil {
		return ip.String()
	}
	return key
}

// BanKey returns the key an automatic ban (honeypot, temp-ban) should use for a
// client address: the address itself, or for IPv6 its enclosing /v6Prefix
// network. IPv6 clients typically hold a whole /64 and scanners rotate through
// it freely, so banning the single address achieves nothing. v6Prefix <= 0 or
// >= 128 bans the single address.
func BanKey(ip string, v6Prefix int) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil || v6Prefix <= 0 || v6Prefix >= 128 {
		return ip
	}
	mask := net.CIDRMask(v6Prefix, 128)
	return (&net.IPNet{IP: parsed.Mask(mask), Mask: mask}).String()
}

// New creates a Blacklist, loading any previously persisted entries from file.
// whitelist accepts plain IPs ("1.2.3.4") or CIDRs ("10.0.0.0/8"). A corrupt
// file is moved aside (never silently overwritten) and loading starts empty.
func New(file string, whitelist []string) (*Blacklist, error) {
	b := &Blacklist{
		entries: make(map[string]Entry),
		cidrs:   make(map[maskShape]map[string]Entry),
		file:    file,
	}
	b.SetWhitelist(whitelist)
	if file == "" {
		return b, nil
	}

	data, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return b, nil
	}
	if err != nil {
		return nil, err
	}
	var list []Entry
	if err := json.Unmarshal(data, &list); err != nil {
		// Starting empty and carrying on would let the next ban overwrite the
		// file, losing every stored ban for good. Set it aside for inspection.
		bad := fmt.Sprintf("%s.corrupt-%s", file, time.Now().UTC().Format("20060102T150405Z"))
		if rerr := os.Rename(file, bad); rerr != nil {
			return nil, fmt.Errorf("blacklist file %s is corrupt (%v) and could not be moved aside: %w", file, err, rerr)
		}
		log.Printf("blacklist: WARNING %s is corrupt (%v); moved it to %s and starting with an empty blacklist", file, err, bad)
		return b, nil
	}
	for _, e := range list {
		if e.expired() {
			continue // drop bans that lapsed while we were down
		}
		e.IP = NormalizeKey(e.IP)
		if m := b.bucketLocked(e.IP, true); m != nil {
			m[e.IP] = e
		} else {
			log.Printf("blacklist: skipping unparseable entry %q", e.IP)
		}
	}
	return b, nil
}

// SetWhitelist replaces the whitelist (e.g. on config reload).
func (b *Blacklist) SetWhitelist(specs []string) {
	nets := ParseNets(specs)
	b.whitelist.Store(&nets)
}

func (b *Blacklist) wl() []*net.IPNet { return *b.whitelist.Load() }

// bucketLocked returns the map an entry for key lives in: the exact-IP map, or
// the group for the key's CIDR prefix length (created if create is set). It
// returns nil for an unparseable CIDR, or a missing group when !create.
func (b *Blacklist) bucketLocked(key string, create bool) map[string]Entry {
	if !isCIDR(key) {
		return b.entries
	}
	_, ipnet, err := net.ParseCIDR(key)
	if err != nil {
		return nil
	}
	ones, bits := ipnet.Mask.Size()
	shape := maskShape{ones, bits}
	m := b.cidrs[shape]
	if m == nil && create {
		m = make(map[string]Entry)
		b.cidrs[shape] = m
	}
	return m
}

// pruneLocked drops empty CIDR groups so lookups don't probe them.
func (b *Blacklist) pruneLocked() {
	for shape, m := range b.cidrs {
		if len(m) == 0 {
			delete(b.cidrs, shape)
		}
	}
}

// IsBlocked reports whether an IP is currently blacklisted, either by an exact
// match or because it falls within a blacklisted CIDR range. Expired exact bans
// are removed lazily on lookup; a whitelisted IP is never reported as blocked,
// even if it has an exact ban (e.g. one made before it was whitelisted) or sits
// inside a banned range.
func (b *Blacklist) IsBlocked(ip string) bool {
	_, blocked := b.Lookup(ip)
	return blocked
}

// Lookup is IsBlocked that also returns the ban responsible: the exact entry if
// there is one, otherwise a covering CIDR range (any one, if several cover it).
func (b *Blacklist) Lookup(ip string) (Entry, bool) {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	key := ip
	if parsed != nil {
		key = parsed.String()
		if containsIP(b.wl(), parsed) {
			return Entry{}, false
		}
	}

	b.mu.RLock()
	e, ok := b.entries[key]
	hasCIDRs := len(b.cidrs) > 0
	b.mu.RUnlock()
	if ok {
		if !e.expired() {
			return e, true
		}
		b.removeExpired(key) // then fall through: a CIDR ban may still cover it
	}

	if !hasCIDRs || parsed == nil {
		return Entry{}, false
	}
	ip4 := parsed.To4()
	b.mu.RLock()
	defer b.mu.RUnlock()
	for shape, m := range b.cidrs {
		addr := parsed
		if shape.bits == 32 {
			if ip4 == nil {
				continue
			}
			addr = ip4
		} else if ip4 != nil {
			continue
		}
		mask := net.CIDRMask(shape.ones, shape.bits)
		network := (&net.IPNet{IP: addr.Mask(mask), Mask: mask}).String()
		if e, ok := m[network]; ok && !e.expired() {
			return e, true
		}
	}
	return Entry{}, false
}

// removeExpired deletes ip's exact entry only if it is still expired once the
// write lock is held — a concurrent Add may have replaced it with a fresh or
// permanent ban since the caller looked.
func (b *Blacklist) removeExpired(ip string) {
	b.mu.Lock()
	e, ok := b.entries[ip]
	if !ok || !e.expired() {
		b.mu.Unlock()
		return
	}
	delete(b.entries, ip)
	snap := b.changedLocked()
	b.mu.Unlock()
	b.persist(snap)
}

// Sweep drops every expired ban (exact IPs and CIDR ranges) and persists the
// result if anything changed, returning how many were dropped. IsBlocked already
// ignores expired bans; sweeping keeps them out of List and the file for IPs
// that never come back. Call periodically.
func (b *Blacklist) Sweep() int {
	b.mu.Lock()
	n := sweepMap(b.entries)
	for _, m := range b.cidrs {
		n += sweepMap(m)
	}
	if n == 0 {
		b.mu.Unlock()
		return 0
	}
	b.pruneLocked()
	snap := b.changedLocked()
	b.mu.Unlock()
	b.persist(snap)
	return n
}

func sweepMap(m map[string]Entry) int {
	n := 0
	for k, e := range m {
		if e.expired() {
			delete(m, k)
			n++
		}
	}
	return n
}

// List returns a snapshot of all current (unexpired) entries.
func (b *Blacklist) List() []Entry {
	b.mu.RLock()
	all := b.snapshotLocked()
	b.mu.RUnlock()
	live := all[:0]
	for _, e := range all {
		if !e.expired() {
			live = append(live, e)
		}
	}
	return live
}

// IsWhitelisted reports whether an IP should never be blacklisted.
func (b *Blacklist) IsWhitelisted(ip string) bool {
	return Matches(b.wl(), ip)
}

// Add permanently blacklists an IP or CIDR range (e.g. "1.2.3.4" or
// "1.2.3.0/24") and persists the set. No-op for whitelisted IPs. Returns true if
// the entry became (or was upgraded to) permanently blocked.
func (b *Blacklist) Add(ip, reason, path string) bool {
	return b.add(ip, reason, path, time.Time{})
}

// AddTemp blacklists an IP or CIDR range until now+dur. No-op for whitelisted
// IPs or entries that are already permanently blocked. Returns true if a new
// temporary ban was set.
func (b *Blacklist) AddTemp(ip, reason string, dur time.Duration) bool {
	return b.add(ip, reason, "", time.Now().UTC().Add(dur))
}

// add applies one ban and persists it if anything changed.
func (b *Blacklist) add(ip, reason, path string, until time.Time) bool {
	b.mu.Lock()
	added, changed := b.addLocked(ip, reason, path, until)
	if !changed {
		b.mu.Unlock()
		return added
	}
	snap := b.changedLocked()
	b.mu.Unlock()
	b.persist(snap)
	return added
}

// AddMany applies a batch of bans (e.g. an import) with a single write to
// disk, returning how many became new or upgraded bans. Each entry's Until
// decides permanent (zero) or temporary; entries already expired are skipped.
// Keys are normalized and whitelisted IPs skipped, as with Add.
func (b *Blacklist) AddMany(entries []Entry) int {
	n, changed := 0, false
	b.mu.Lock()
	for _, e := range entries {
		if e.expired() {
			continue
		}
		added, ch := b.addLocked(e.IP, e.Reason, e.Path, e.Until)
		if added {
			n++
		}
		changed = changed || ch
	}
	if !changed {
		b.mu.Unlock()
		return n
	}
	snap := b.changedLocked()
	b.mu.Unlock()
	b.persist(snap)
	return n
}

// addLocked applies a ban with temp/permanent reconciliation: a permanent ban
// outranks (and upgrades) a temporary one, and re-banning an active temporary
// entry only ever extends it. added reports a new or upgraded ban (worth
// logging); changed reports whether the set needs persisting. Caller holds
// b.mu for writing.
func (b *Blacklist) addLocked(ip, reason, path string, until time.Time) (added, changed bool) {
	key := NormalizeKey(ip)
	if !isCIDR(key) && b.IsWhitelisted(key) {
		return false, false
	}
	m := b.bucketLocked(key, true)
	if m == nil {
		return false, false // unparseable CIDR
	}
	existing, exists := m[key]
	if exists && !existing.expired() {
		permanentReq := until.IsZero()
		switch {
		case permanentReq && existing.Until.IsZero():
			return false, false // already permanent, nothing to do
		case permanentReq:
			// Upgrade an active temporary ban to permanent.
		case existing.Until.IsZero():
			return false, false // permanent ban outranks a temporary one
		default:
			// Refresh an existing temporary ban, extend if later.
			if !until.After(existing.Until) {
				return false, false
			}
			existing.Until = until
			m[key] = existing
			return false, true // already blocked; don't re-log
		}
	}
	m[key] = Entry{IP: key, Reason: reason, Path: path, Timestamp: time.Now().UTC(), Until: until}
	return true, true
}

// Remove deletes an IP or CIDR range from the blacklist and persists the change.
// Keys are normalized first, so a CIDR may be passed as originally entered or in
// normalized form. Returns true if an entry was present.
func (b *Blacklist) Remove(ip string) bool {
	key := NormalizeKey(ip)
	b.mu.Lock()
	m := b.bucketLocked(key, false)
	if _, ok := m[key]; !ok {
		b.mu.Unlock()
		return false
	}
	delete(m, key)
	b.pruneLocked()
	snap := b.changedLocked()
	b.mu.Unlock()
	b.persist(snap)
	return true
}

// Count returns the number of blacklisted entries (exact IPs and CIDR ranges).
func (b *Blacklist) Count() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	n := len(b.entries)
	for _, m := range b.cidrs {
		n += len(m)
	}
	return n
}

func (b *Blacklist) snapshotLocked() []Entry {
	list := make([]Entry, 0, len(b.entries))
	for _, e := range b.entries {
		list = append(list, e)
	}
	for _, m := range b.cidrs {
		for _, e := range m {
			list = append(list, e)
		}
	}
	return list
}

// pendingWrite is a copy of the set taken right after a mutation, tagged with a
// generation so persist can tell which of two racing writes is newer.
type pendingWrite struct {
	list []Entry
	gen  uint64
}

// changedLocked records a mutation and returns the state to persist. Caller
// holds b.mu for writing.
func (b *Blacklist) changedLocked() pendingWrite {
	b.gen++
	return pendingWrite{list: b.snapshotLocked(), gen: b.gen}
}

// persist atomically writes the blacklist to disk: write to a temp file, fsync
// it so the data is durable, then rename over the target. Writes are serialized
// (they share one temp file) and a snapshot older than one already on disk is
// skipped, so concurrent bans can neither corrupt the file nor roll it back.
// Every failure is logged so a broken persistence path (read-only mount, full
// disk) is visible rather than silently dropping bans on restart.
func (b *Blacklist) persist(w pendingWrite) {
	if b.file == "" {
		return
	}
	b.persistMu.Lock()
	defer b.persistMu.Unlock()
	if w.gen <= b.savedGen {
		return // a newer snapshot already reached disk
	}
	data, err := json.MarshalIndent(w.list, "", "  ")
	if err != nil {
		log.Printf("blacklist: marshal failed: %v", err)
		return
	}
	tmp := b.file + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		log.Printf("blacklist: open %s failed: %v", tmp, err)
		return
	}
	if _, err := f.Write(data); err != nil {
		log.Printf("blacklist: write %s failed: %v", tmp, err)
		_ = f.Close()
		return
	}
	if err := f.Sync(); err != nil {
		log.Printf("blacklist: fsync %s failed: %v", tmp, err)
		_ = f.Close()
		return
	}
	if err := f.Close(); err != nil {
		log.Printf("blacklist: close %s failed: %v", tmp, err)
		return
	}
	if err := os.Rename(tmp, b.file); err != nil {
		log.Printf("blacklist: rename %s -> %s failed: %v", tmp, b.file, err)
		return
	}
	b.savedGen = w.gen
}
