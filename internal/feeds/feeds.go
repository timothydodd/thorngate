// Package feeds keeps whitelist groups in sync with published IP-range lists
// (search-crawler feeds such as https://openai.com/searchbot.json). Each feed
// is polled on its own interval; a successful fetch replaces that feed's group
// wholesale, so ranges the feed drops leave the whitelist, and any existing
// bans inside its ranges are lifted. A failed or empty fetch keeps the last
// good list.
package feeds

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"thorngate/internal/activity"
	"thorngate/internal/blacklist"
	"thorngate/internal/config"
)

const (
	maxBody      = 4 << 20 // a crawler feed is a few KB; refuse anything absurd
	fetchTimeout = 30 * time.Second
	// Ranges broader than these are dropped: a feed listing 0.0.0.0/0 (or any
	// huge block) would otherwise switch off banning for the whole internet.
	minV4Prefix = 8
	minV6Prefix = 16
)

// retryDelay is how soon a failed fetch is retried (capped at the interval).
var retryDelay = 5 * time.Minute

// Store is the slice of the blacklist the manager drives.
type Store interface {
	SetWhitelistGroup(name string, specs []string)
	RemoveCovered(specs []string) []blacklist.Entry
}

// Status describes one feed for the admin portal.
type Status struct {
	URL       string    `json:"url"`
	Interval  string    `json:"interval"`
	Prefixes  []string  `json:"prefixes"`
	LastFetch time.Time `json:"last_fetch,omitempty"` // last attempt
	LastOK    time.Time `json:"last_ok,omitempty"`    // last successful fetch
	Error     string    `json:"error,omitempty"`      // last attempt's error
}

type feed struct {
	cfg    config.WhitelistFeed
	cancel context.CancelFunc
}

// Manager runs one poller per configured feed.
type Manager struct {
	store  Store
	act    *activity.Log // nil-safe
	client *http.Client

	mu     sync.Mutex
	feeds  map[string]*feed // by URL
	status map[string]*Status
}

// New returns a Manager with no feeds; call Apply to start them. Feed changes
// and failures are recorded to act, which may be nil.
func New(store Store, act *activity.Log) *Manager {
	return &Manager{
		store:  store,
		act:    act,
		client: &http.Client{Timeout: fetchTimeout},
		feeds:  make(map[string]*feed),
		status: make(map[string]*Status),
	}
}

// Apply reconciles the running pollers with a (re)loaded config: removed feeds
// stop and their whitelist group is dropped, new or changed ones start and
// fetch right away, unchanged ones keep running undisturbed.
func (m *Manager) Apply(list []config.WhitelistFeed) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := make(map[string]config.WhitelistFeed, len(list))
	for _, f := range list {
		want[f.URL] = f
	}
	for u, f := range m.feeds {
		if w, ok := want[u]; ok && w.IntervalDur() == f.cfg.IntervalDur() {
			continue
		}
		f.cancel()
		delete(m.feeds, u)
		if _, ok := want[u]; !ok {
			delete(m.status, u)
			m.store.SetWhitelistGroup(u, nil)
			log.Printf("whitelist feed %s: removed", u)
			m.act.Addf(activity.Feed, activity.Info, "", u, "Feed removed from config; its ranges left the whitelist")
		}
	}
	for u, w := range want {
		if _, ok := m.feeds[u]; ok {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.feeds[u] = &feed{cfg: w, cancel: cancel}
		st := m.status[u]
		if st == nil {
			st = &Status{URL: u}
			m.status[u] = st
		}
		st.Interval = w.Interval
		go m.run(ctx, w)
	}
}

// Stop ends every poller. Whitelist groups are left in place.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for u, f := range m.feeds {
		f.cancel()
		delete(m.feeds, u)
	}
}

// Statuses returns every feed's state, sorted by URL.
func (m *Manager) Statuses() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.status))
	for _, st := range m.status {
		s := *st
		s.Prefixes = append([]string{}, st.Prefixes...)
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URL < out[j].URL })
	return out
}

func (m *Manager) run(ctx context.Context, f config.WhitelistFeed) {
	for {
		wait := f.IntervalDur()
		if err := m.refresh(ctx, f.URL); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("whitelist feed %s: %v (keeping the last good list)", f.URL, err)
			wait = min(retryDelay, wait)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// refresh fetches one feed and, if it parses to a non-empty list, makes it that
// feed's whitelist group and lifts bans inside it.
func (m *Manager) refresh(ctx context.Context, url string) error {
	prefixes, err := m.fetch(ctx, url)

	m.mu.Lock()
	st := m.status[url]
	if _, live := m.feeds[url]; !live || ctx.Err() != nil {
		m.mu.Unlock() // removed by a reload mid-fetch: don't resurrect its group
		return ctx.Err()
	}
	st.LastFetch = time.Now()
	if err != nil {
		// Only the first failure (or a new kind of failure) is recorded, so a
		// long outage retried every few minutes doesn't flood the log.
		if st.Error != err.Error() {
			m.act.Addf(activity.Feed, activity.Warn, "", url, "Fetch failed, keeping the last good list: %v", err)
		}
		st.Error = err.Error()
		m.mu.Unlock()
		return err
	}
	first, recovered := st.LastOK.IsZero(), st.Error != ""
	added, dropped := diff(st.Prefixes, prefixes)
	st.Prefixes, st.LastOK, st.Error = prefixes, st.LastFetch, ""
	// Under m.mu so a concurrent Apply removing this feed can't interleave.
	m.store.SetWhitelistGroup(url, prefixes)
	m.mu.Unlock()

	switch {
	case first:
		m.act.Addf(activity.Feed, activity.Info, "", url, "Loaded %d ranges", len(prefixes))
	case added > 0 || dropped > 0:
		m.act.Addf(activity.Feed, activity.Info, "", url, "Updated: %d ranges (+%d added, -%d removed)", len(prefixes), added, dropped)
	case recovered:
		m.act.Addf(activity.Feed, activity.Info, "", url, "Fetching again after failures; %d ranges, unchanged", len(prefixes))
	}
	if added > 0 || dropped > 0 {
		log.Printf("whitelist feed %s: %d ranges (+%d, -%d)", url, len(prefixes), added, dropped)
	}
	for _, e := range m.store.RemoveCovered(prefixes) {
		log.Printf("UNBANNED ip=%s reason=%s whitelisted by feed %s", e.IP, e.Reason, url)
		m.act.Addf(activity.Unban, activity.Info, e.IP, url, "Unbanned (was %s): inside a whitelist feed range", e.Reason)
	}
	return nil
}

func (m *Manager) fetch(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "thorngate (whitelist feed)")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("response larger than %d bytes", maxBody)
	}
	return Parse(body)
}

// Parse extracts IP ranges from a feed body: the {"prefixes": [{"ipv4Prefix":
// ...}, {"ipv6Prefix": ...}]} JSON used by OpenAI, Google and Bing, or plain
// text with one IP/CIDR per line. Ranges come back normalized, deduplicated
// and sorted. Unparseable or overly broad entries are skipped; a body yielding
// no ranges at all is an error, so a broken feed can't empty the whitelist.
func Parse(body []byte) ([]string, error) {
	var raw []string
	if b := bytes.TrimSpace(body); len(b) > 0 && (b[0] == '{' || b[0] == '[') {
		var doc struct {
			Prefixes []struct {
				IPv4 string `json:"ipv4Prefix"`
				IPv6 string `json:"ipv6Prefix"`
			} `json:"prefixes"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			return nil, fmt.Errorf("parse JSON: %w", err)
		}
		for _, p := range doc.Prefixes {
			raw = append(raw, p.IPv4, p.IPv6)
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(body))
		for sc.Scan() {
			line, _, _ := strings.Cut(sc.Text(), "#")
			raw = append(raw, strings.Fields(line)...)
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}

	seen := make(map[string]bool)
	var out []string
	for _, s := range raw {
		key, ok := normalize(s)
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	if len(out) == 0 {
		return nil, errors.New("feed lists no usable IP ranges")
	}
	sort.Strings(out)
	return out, nil
}

// normalize canonicalizes an IP or CIDR, rejecting junk and too-broad ranges.
func normalize(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return "", false
		}
		return blacklist.NormalizeKey(s), true
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return "", false
	}
	ones, bits := n.Mask.Size()
	if (bits == 32 && ones < minV4Prefix) || (bits == 128 && ones < minV6Prefix) {
		log.Printf("whitelist feed: ignoring overly broad range %s", s)
		return "", false
	}
	return n.String(), true
}

// diff counts entries of next missing from prev (added) and vice versa.
func diff(prev, next []string) (added, dropped int) {
	in := make(map[string]bool, len(prev))
	for _, p := range prev {
		in[p] = true
	}
	for _, n := range next {
		if !in[n] {
			added++
		}
		delete(in, n)
	}
	return added, len(in)
}
