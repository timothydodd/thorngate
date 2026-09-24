// Package archive keeps a long request history on disk so the admin portal can
// search weeks of traffic without holding it in memory. Every observed request
// is appended as one JSON line to an hourly segment file. When the hour closes
// the segment is gzipped and a small index (per-IP and per-path counts, totals)
// is written beside it, so most questions — an IP's history, top talkers, the
// traffic chart — are answered from indexes, reading only the hours that
// matter. Segments older than the retention period are deleted.
//
//	dir/2026-09-23T14.jsonl      current hour, appended to live
//	dir/2026-09-23T13.jsonl.gz   sealed hour
//	dir/2026-09-23T13.idx.json   its index
//
// Standard library only, like the rest of thorngate.
package archive

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"thorngate/internal/stats"
)

const (
	hourLayout = "2006-01-02T15"
	extPlain   = ".jsonl"
	extGz      = ".jsonl.gz"
	extIdx     = ".idx.json"

	// queueSize buffers events between the request path and the writer. Past
	// it, events are dropped (and counted) rather than slowing the proxy.
	queueSize = 8192

	// maxIndexPaths caps distinct paths recorded per hour's index; scanners can
	// probe thousands of unique paths. The overflow is counted in OtherPaths.
	maxIndexPaths = 2000
)

// Archive appends events to hourly segments and answers stats.History queries
// from them. Create with Open; all methods are safe for concurrent use.
type Archive struct {
	dir       string
	retention time.Duration

	ch       chan stats.Event
	flushReq chan chan struct{}
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	dropped  atomic.Uint64

	// segMu keeps readers and sealing/pruning apart: sealing renames and deletes
	// files, which fails on Windows (and races on any OS) while a reader has
	// them open. Readers RLock around each segment they read.
	segMu sync.RWMutex
}

// Open prepares dir (creating it if needed), seals any segments a previous run
// left unsealed, prunes expired ones, and starts the writer.
func Open(dir string, retention time.Duration) (*Archive, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	a := &Archive{
		dir:       dir,
		retention: retention,
		ch:        make(chan stats.Event, queueSize),
		flushReq:  make(chan chan struct{}),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	cur := hourKey(time.Now())
	segs, err := a.segments(time.Time{})
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		if s.plain && s.key != cur {
			if err := a.seal(s.key); err != nil {
				log.Printf("archive: seal %s: %v", s.key, err)
			}
		}
	}
	a.prune()
	go a.run()
	return a, nil
}

// Append queues an event for writing. It never blocks: if the writer has
// fallen behind, the event is dropped and counted (see Dropped).
func (a *Archive) Append(e stats.Event) {
	select {
	case a.ch <- e:
	default:
		a.dropped.Add(1)
	}
}

// Retention returns how long history is kept.
func (a *Archive) Retention() time.Duration { return a.retention }

// Dropped returns how many events were discarded because the queue was full.
func (a *Archive) Dropped() uint64 { return a.dropped.Load() }

// Close drains queued events to disk and stops the writer. The current hour's
// segment is left unsealed; the next Open (or the hour rolling over) seals it.
// Appends after Close are silently dropped.
func (a *Archive) Close() {
	a.stopOnce.Do(func() { close(a.stop) })
	<-a.done
}

// Usage reports how many segments are on disk and their total size.
func (a *Archive) Usage() (segments int, bytes int64) {
	entries, _ := os.ReadDir(a.dir)
	seen := map[string]bool{}
	for _, de := range entries {
		key, ok := segKey(de.Name())
		if !ok {
			continue
		}
		seen[key] = true
		if info, err := de.Info(); err == nil {
			bytes += info.Size()
		}
	}
	return len(seen), bytes
}

func hourKey(t time.Time) string { return t.UTC().Format(hourLayout) }

func (a *Archive) path(key, ext string) string { return filepath.Join(a.dir, key+ext) }

// run is the single writer goroutine.
func (a *Archive) run() {
	defer close(a.done)
	var (
		cur string
		f   *os.File
		bw  *bufio.Writer
	)
	closeCur := func(seal bool) {
		if f == nil {
			return
		}
		if err := bw.Flush(); err != nil {
			log.Printf("archive: flush %s: %v", cur, err)
		}
		_ = f.Close()
		f, bw = nil, nil
		if seal {
			if err := a.seal(cur); err != nil {
				log.Printf("archive: seal %s: %v", cur, err)
			}
		}
		cur = ""
	}
	write := func(e *stats.Event) {
		// Key by the later of the event's hour and the open segment's: an event
		// stamped just before the hour rolled over joins the current segment
		// instead of reopening a sealed one. Queries filter by e.Time anyway.
		key := hourKey(e.Time)
		if cur != "" && key < cur {
			key = cur
		}
		if key != cur {
			closeCur(true)
			var err error
			if f, err = openAppend(a.path(key, extPlain)); err != nil {
				log.Printf("archive: open segment %s: %v", key, err)
				return
			}
			cur, bw = key, bufio.NewWriterSize(f, 64<<10)
		}
		line, err := json.Marshal(e)
		if err != nil {
			return
		}
		_, _ = bw.Write(line)
		_ = bw.WriteByte('\n')
	}

	// drain writes everything already queued, so a flush or shutdown never
	// leaves behind events that were appended before it was requested.
	drain := func() {
		for {
			select {
			case e := <-a.ch:
				write(&e)
			default:
				return
			}
		}
	}

	flush := time.NewTicker(time.Second)
	defer flush.Stop()
	maint := time.NewTicker(time.Minute)
	defer maint.Stop()
	for {
		select {
		case e := <-a.ch:
			write(&e)
		case <-flush.C:
			if bw != nil {
				_ = bw.Flush()
			}
		case reply := <-a.flushReq:
			drain()
			if bw != nil {
				_ = bw.Flush()
			}
			close(reply)
		case <-maint.C:
			// Seal the segment once its hour has passed even if no newer
			// event arrived to trigger the rollover.
			if cur != "" && hourKey(time.Now()) > cur {
				closeCur(true)
			}
			a.prune()
		case <-a.stop:
			drain()
			closeCur(false)
			return
		}
	}
}

// openAppend opens a segment for appending. A segment cut off mid-line by a
// crash gets a newline first, so the next event starts on a line of its own.
func openAppend(p string) (*os.File, error) {
	f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err == nil && info.Size() > 0 {
		last := make([]byte, 1)
		if _, err := f.ReadAt(last, info.Size()-1); err == nil && last[0] != '\n' {
			_, _ = f.Write([]byte{'\n'})
		}
	}
	return f, nil
}

// sync asks the writer to write out everything appended so far, so a query
// sees it. It gives up after a second rather than stall a request if the
// writer is busy.
func (a *Archive) sync() {
	reply := make(chan struct{})
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	select {
	case a.flushReq <- reply:
	case <-a.done:
		return
	case <-timeout.C:
		return
	}
	select {
	case <-reply:
	case <-timeout.C:
	}
}

// index summarizes one sealed hour.
type index struct {
	Total      int            `json:"total"`
	Blocked    int            `json:"blocked"` // requests not proxied
	IPs        map[string]int `json:"ips"`
	Paths      map[string]int `json:"paths"`
	OtherPaths int            `json:"other_paths,omitempty"` // past maxIndexPaths
}

func newIndex() *index { return &index{IPs: map[string]int{}, Paths: map[string]int{}} }

func (x *index) add(e *stats.Event) {
	x.Total++
	if e.Outcome != "proxied" {
		x.Blocked++
	}
	x.IPs[e.IP]++
	if _, ok := x.Paths[e.Path]; ok || len(x.Paths) < maxIndexPaths {
		x.Paths[e.Path]++
	} else {
		x.OtherPaths++
	}
}

// seal gzips a finished plain segment, writes its index, then removes the plain
// file. Each output is written to a temp file and renamed, and the plain file
// goes last, so a crash at any point leaves a segment Open can re-seal.
func (a *Archive) seal(key string) error {
	plain := a.path(key, extPlain)
	in, err := os.Open(plain)
	if err != nil {
		return err
	}
	gzTmp := a.path(key, extGz+".tmp")
	out, err := os.Create(gzTmp)
	if err != nil {
		_ = in.Close()
		return err
	}
	zw := gzip.NewWriter(out)
	idx := newIndex()
	err = eachLine(in, func(line []byte, e *stats.Event) bool {
		_, _ = zw.Write(line)
		_, _ = zw.Write([]byte{'\n'})
		idx.add(e)
		return true
	})
	_ = in.Close()
	if err == nil {
		err = zw.Close()
	}
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(gzTmp)
		return err
	}
	idxData, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	idxTmp := a.path(key, extIdx+".tmp")
	if err := os.WriteFile(idxTmp, idxData, 0o644); err != nil {
		return err
	}

	a.segMu.Lock()
	defer a.segMu.Unlock()
	if err := os.Rename(gzTmp, a.path(key, extGz)); err != nil {
		return err
	}
	if err := os.Rename(idxTmp, a.path(key, extIdx)); err != nil {
		return err
	}
	return os.Remove(plain)
}

// prune deletes segments older than the retention period.
func (a *Archive) prune() {
	cutoff := hourKey(time.Now().Add(-a.retention))
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return
	}
	a.segMu.Lock()
	defer a.segMu.Unlock()
	for _, de := range entries {
		if key, ok := segKey(de.Name()); ok && key < cutoff {
			_ = os.Remove(filepath.Join(a.dir, de.Name()))
		}
	}
}

// segKey extracts the hour key from a segment file name.
func segKey(name string) (string, bool) {
	for _, ext := range []string{extPlain, extGz, extIdx} {
		if key, ok := strings.CutSuffix(name, ext); ok {
			if _, err := time.Parse(hourLayout, key); err == nil {
				return key, true
			}
		}
	}
	return "", false
}

// segment is one hour on disk.
type segment struct {
	key   string
	hour  time.Time
	plain bool // unsealed .jsonl present (current hour, or awaiting seal)
	gz    bool
	idx   bool
}

// segments lists the hours on disk whose hour ends after since, newest first.
func (a *Archive) segments(since time.Time) ([]segment, error) {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return nil, err
	}
	byKey := map[string]*segment{}
	for _, de := range entries {
		name := de.Name()
		key, ok := segKey(name)
		if !ok {
			continue
		}
		s := byKey[key]
		if s == nil {
			h, _ := time.Parse(hourLayout, key)
			s = &segment{key: key, hour: h}
			byKey[key] = s
		}
		switch {
		case strings.HasSuffix(name, extPlain):
			s.plain = true
		case strings.HasSuffix(name, extGz):
			s.gz = true
		case strings.HasSuffix(name, extIdx):
			s.idx = true
		}
	}
	out := make([]segment, 0, len(byKey))
	for _, s := range byKey {
		if !s.plain && !s.gz {
			continue // stray index
		}
		// A segment may hold events up to a few ms before its hour (see run),
		// so only whole hours strictly before since are skipped.
		if !since.IsZero() && !s.hour.Add(time.Hour).After(since) {
			continue
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key > out[j].key })
	return out, nil
}

// sealed reports whether a segment can be answered from its index.
func (s segment) sealed() bool { return !s.plain && s.gz && s.idx }

// covered reports whether every event in the segment falls inside f's time
// range, so index counts apply without checking individual timestamps.
func (s segment) covered(f *stats.Filter) bool {
	return (f.Since.IsZero() || !s.hour.Before(f.Since)) &&
		(f.Until.IsZero() || !s.hour.Add(time.Hour).After(f.Until))
}

func (a *Archive) readIndex(key string) (*index, error) {
	data, err := os.ReadFile(a.path(key, extIdx))
	if err != nil {
		return nil, err
	}
	x := newIndex()
	return x, json.Unmarshal(data, x)
}

// scan calls fn for each event in the segment, oldest first, until fn returns
// false. Unreadable lines are skipped.
func (a *Archive) scan(s segment, fn func(e *stats.Event) bool) error {
	a.segMu.RLock()
	defer a.segMu.RUnlock()
	var r io.Reader
	f, err := os.Open(a.path(s.key, extPlain))
	if errors.Is(err, os.ErrNotExist) {
		// Sealed since it was listed (or never plain): read the gzip.
		if f, err = os.Open(a.path(s.key, extGz)); err != nil {
			return err
		}
		zr, err := gzip.NewReader(f)
		if err != nil {
			_ = f.Close()
			return err
		}
		defer zr.Close()
		r = zr
	} else if err != nil {
		return err
	} else {
		r = f
	}
	defer f.Close()
	return eachLine(r, func(_ []byte, e *stats.Event) bool { return fn(e) })
}

// eachLine decodes JSON-lines events from r. A truncated or corrupt line (e.g.
// the tail of a crashed write) is skipped rather than failing the segment.
func eachLine(r io.Reader, fn func(line []byte, e *stats.Event) bool) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			line = trimNewline(line)
			var e stats.Event
			if len(line) > 0 && json.Unmarshal(line, &e) == nil {
				if !fn(line, &e) {
					return nil
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
