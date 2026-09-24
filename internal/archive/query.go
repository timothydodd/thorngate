package archive

import (
	"time"

	"thorngate/internal/stats"
)

var _ stats.History = (*Archive)(nil)

// Query returns one page of matching events, newest first. It works in two
// passes so memory stays bounded however long the range: first count the
// matches in each hour (from its index when the filter allows, else by
// scanning), then read only the hours the requested page falls in.
func (a *Archive) Query(f stats.Filter, page, pageSize int) (stats.RecentPage, error) {
	if err := f.Compile(); err != nil {
		return stats.RecentPage{}, err
	}
	a.sync()
	segs, err := a.segments(f.Since)
	if err != nil {
		return stats.RecentPage{}, err
	}

	counts := make([]int, len(segs))
	total := 0
	for i, s := range segs {
		n, err := a.countMatches(s, &f)
		if err != nil {
			return stats.RecentPage{}, err
		}
		counts[i] = n
		total += n
	}

	page, pageSize, start, end := stats.PageBounds(total, page, pageSize)
	events := make([]stats.Event, 0, end-start)
	offset := 0 // matches in newer segments than s
	for i, s := range segs {
		if offset >= end {
			break
		}
		if counts[i] == 0 || offset+counts[i] <= start {
			offset += counts[i]
			continue
		}
		matched, err := a.matchesNewestFirst(s, &f)
		if err != nil {
			return stats.RecentPage{}, err
		}
		lo, hi := max(start-offset, 0), min(end-offset, len(matched))
		if lo < hi {
			events = append(events, matched[lo:hi]...)
		}
		offset += counts[i]
	}

	ipCounts, err := a.ipCounts(segs, &f, events)
	if err != nil {
		return stats.RecentPage{}, err
	}
	return stats.RecentPage{
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Events:   events,
		IPCounts: ipCounts,
	}, nil
}

// countMatches counts f's matches in one segment, from its index when that is
// exact (a sealed hour wholly inside the range, filtered at most by one IP).
// An IP the index has never seen skips the segment even for richer filters.
func (a *Archive) countMatches(s segment, f *stats.Filter) (int, error) {
	if s.sealed() {
		if x, err := a.readIndex(s.key); err == nil {
			ip := f.ExactIP()
			if ip != "" && x.IPs[ip] == 0 {
				return 0, nil
			}
			if f.Indexed() && s.covered(f) {
				if ip != "" {
					return x.IPs[ip], nil
				}
				return x.Total, nil
			}
		}
	}
	n := 0
	err := a.scan(s, func(e *stats.Event) bool {
		if f.Match(e) {
			n++
		}
		return true
	})
	return n, err
}

// matchesNewestFirst reads one segment's matching events, newest first.
func (a *Archive) matchesNewestFirst(s segment, f *stats.Filter) ([]stats.Event, error) {
	var out []stats.Event
	err := a.scan(s, func(e *stats.Event) bool {
		if f.Match(e) {
			out = append(out, *e)
		}
		return true
	})
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, err
}

// ipCounts totals, across f's whole time range, the requests from each IP that
// appears in events — ignoring f's other criteria, matching Collector.Query.
func (a *Archive) ipCounts(segs []segment, f *stats.Filter, events []stats.Event) (map[string]int, error) {
	counts := make(map[string]int, len(events))
	for _, e := range events {
		counts[e.IP] = 0
	}
	if len(counts) == 0 {
		return counts, nil
	}
	for _, s := range segs {
		if s.sealed() && s.covered(f) {
			if x, err := a.readIndex(s.key); err == nil {
				for ip := range counts {
					counts[ip] += x.IPs[ip]
				}
				continue
			}
		}
		err := a.scan(s, func(e *stats.Event) bool {
			if _, ok := counts[e.IP]; ok && f.InRange(e.Time) {
				counts[e.IP]++
			}
			return true
		})
		if err != nil {
			return nil, err
		}
	}
	return counts, nil
}

// Top returns the busiest IPs and paths since the given time. Sealed hours are
// merged from their indexes, whose path counts are capped per hour, so path
// totals are approximate on very high-cardinality traffic.
func (a *Archive) Top(since time.Time, n int) (stats.Top, error) {
	a.sync()
	f := stats.Filter{Since: since}
	segs, err := a.segments(since)
	if err != nil {
		return stats.Top{}, err
	}
	ips, paths := map[string]int{}, map[string]int{}
	for _, s := range segs {
		if s.sealed() && s.covered(&f) {
			if x, err := a.readIndex(s.key); err == nil {
				for k, v := range x.IPs {
					ips[k] += v
				}
				for k, v := range x.Paths {
					paths[k] += v
				}
				continue
			}
		}
		err := a.scan(s, func(e *stats.Event) bool {
			if f.InRange(e.Time) {
				ips[e.IP]++
				paths[e.Path]++
			}
			return true
		})
		if err != nil {
			return stats.Top{}, err
		}
	}
	return stats.Top{IPs: stats.TopN(ips, n), Paths: stats.TopN(paths, n)}, nil
}

// IPSummary profiles one client since the given time, reading only the hours
// whose index shows that IP.
func (a *Archive) IPSummary(ip string, since time.Time) (stats.IPSummary, error) {
	f := stats.Filter{IP: ip, Since: since}
	if err := f.Compile(); err != nil {
		return stats.IPSummary{}, err
	}
	a.sync()
	segs, err := a.segments(since)
	if err != nil {
		return stats.IPSummary{}, err
	}
	z := stats.NewSummarizer(f.ExactIP())
	for _, s := range segs {
		if s.sealed() {
			if x, err := a.readIndex(s.key); err == nil && x.IPs[f.ExactIP()] == 0 {
				continue
			}
		}
		matched, err := a.matchesNewestFirst(s, &f)
		if err != nil {
			return stats.IPSummary{}, err
		}
		for i := range matched {
			z.Add(&matched[i])
		}
	}
	return z.Result(), nil
}

// Hourly returns requests and blocked counts per hour since the given time,
// from indexes where sealed. A sealed hour's events are all attributed to that
// hour, including the few ms of stragglers written just after it began.
func (a *Archive) Hourly(since time.Time) ([]stats.Bucket, error) {
	a.sync()
	out, pos := stats.HourlyFrame(since)
	segs, err := a.segments(since)
	if err != nil {
		return nil, err
	}
	for _, s := range segs {
		if s.sealed() {
			if x, err := a.readIndex(s.key); err == nil {
				if i, ok := pos[s.hour.Unix()/60]; ok {
					out[i].Requests += uint64(x.Total)
					out[i].Blocked += uint64(x.Blocked)
				}
				continue
			}
		}
		err := a.scan(s, func(e *stats.Event) bool {
			if i, ok := pos[e.Time.UTC().Truncate(time.Hour).Unix()/60]; ok {
				out[i].Requests++
				if e.Outcome != "proxied" {
					out[i].Blocked++
				}
			}
			return true
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
