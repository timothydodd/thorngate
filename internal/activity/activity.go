// Package activity keeps a log of noteworthy things that happen outside the
// normal request flow — bans and unbans, whitelist feed updates, config
// reloads, admin logins, start-up and shutdown — for the admin portal.
//
// The most recent events are held in memory. With a file configured they are
// also appended to it as JSON lines and read back at start-up; the file is
// rewritten down to the in-memory window whenever it grows past twice that.
package activity

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

// Categories.
const (
	Ban    = "ban"
	Unban  = "unban"
	Feed   = "feed"
	Config = "config"
	Auth   = "auth"
	System = "system"
)

// Levels.
const (
	Info  = "info"
	Warn  = "warn"
	Error = "error"
)

// Event is one activity log entry.
type Event struct {
	Time     time.Time `json:"time"`
	Category string    `json:"category"`
	Level    string    `json:"level"`
	Message  string    `json:"message"`
	// IP is the address or range the event is about, if any.
	IP string `json:"ip,omitempty"`
	// Actor is who or what caused it: an admin user, a feed URL, "system".
	Actor string `json:"actor,omitempty"`
}

// Log is a bounded, optionally persisted activity log. A nil *Log is valid and
// records nothing, so callers never need to check whether it is enabled.
type Log struct {
	mu    sync.Mutex
	buf   []Event // oldest first
	max   int
	file  string
	f     *os.File
	lines int // lines currently in file
}

// New returns a log keeping the last max events, persisted to file when it is
// non-empty. Events already in the file are loaded.
func New(max int, file string) (*Log, error) {
	l := &Log{max: max, file: file}
	if file == "" {
		return l, nil
	}
	if err := l.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	l.f = f
	return l, nil
}

func (l *Log) load() error {
	f, err := os.Open(l.file)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l.lines++
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // a torn last line from a crash, say
		}
		l.buf = append(l.buf, e)
		if len(l.buf) > 2*l.max {
			l.buf = append([]Event(nil), l.buf[len(l.buf)-l.max:]...)
		}
	}
	l.trimLocked()
	return sc.Err()
}

// Add records an event, stamping its time if unset.
func (l *Log) Add(e Event) {
	if l == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Level == "" {
		e.Level = Info
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, e)
	l.trimLocked()
	if l.f == nil {
		return
	}
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		log.Printf("activity: write %s: %v", l.file, err)
		return
	}
	l.lines++
	if l.lines > 2*l.max {
		l.compactLocked()
	}
}

// Addf is Add with a formatted message.
func (l *Log) Addf(category, level, ip, actor, format string, args ...any) {
	if l == nil {
		return
	}
	l.Add(Event{Category: category, Level: level, IP: ip, Actor: actor, Message: fmt.Sprintf(format, args...)})
}

// trimLocked caps the buffer, copying only once it overshoots by a quarter so
// appends stay amortized O(1).
func (l *Log) trimLocked() {
	if len(l.buf) > l.max+l.max/4 {
		l.buf = append([]Event(nil), l.buf[len(l.buf)-l.max:]...)
	}
}

// compactLocked rewrites the file to hold just the in-memory events (temp file
// + rename, so a crash leaves the old file intact). The append handle is closed
// first: Windows can't rename over an open file.
func (l *Log) compactLocked() {
	keep := l.buf
	if len(keep) > l.max {
		keep = keep[len(keep)-l.max:]
	}
	var sb strings.Builder
	for _, e := range keep {
		b, _ := json.Marshal(e)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	tmp := l.file + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o644); err != nil {
		log.Printf("activity: compact %s: %v", l.file, err)
		return
	}
	l.f.Close()
	if err := os.Rename(tmp, l.file); err != nil {
		log.Printf("activity: compact %s: %v", l.file, err)
	} else {
		l.lines = len(keep)
	}
	f, err := os.OpenFile(l.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("activity: reopen %s: %v (no longer persisting)", l.file, err)
		l.f = nil
		return
	}
	l.f = f
}

// Query selects events for the portal. Zero values mean "any".
type Query struct {
	Category string
	Level    string
	Search   string // case-insensitive substring of message, IP or actor
	Offset   int
	Limit    int
}

// List returns matching events newest first, plus the total number matching.
func (l *Log) List(q Query) ([]Event, int) {
	if l == nil {
		return []Event{}, 0
	}
	search := strings.ToLower(q.Search)
	l.mu.Lock()
	defer l.mu.Unlock()
	start := 0
	if len(l.buf) > l.max {
		start = len(l.buf) - l.max
	}
	out := []Event{}
	total := 0
	for i := len(l.buf) - 1; i >= start; i-- {
		e := l.buf[i]
		if q.Category != "" && e.Category != q.Category {
			continue
		}
		if q.Level != "" && e.Level != q.Level {
			continue
		}
		if search != "" && !strings.Contains(strings.ToLower(e.Message+" "+e.IP+" "+e.Actor), search) {
			continue
		}
		total++
		if total > q.Offset && (q.Limit <= 0 || len(out) < q.Limit) {
			out = append(out, e)
		}
	}
	return out, total
}

// Close flushes and closes the file.
func (l *Log) Close() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
}
