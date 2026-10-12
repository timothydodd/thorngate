package admin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"thorngate/internal/activity"
	"thorngate/internal/blacklist"
)

// maxImportBytes caps a blacklist import (a large public blocklist fits).
const maxImportBytes = 5 << 20

func (s *server) handleListBlacklist(w http.ResponseWriter, r *http.Request) {
	list := s.Blacklist.List()
	sort.Slice(list, func(i, j int) bool { return list[i].Timestamp.After(list[j].Timestamp) })
	writeJSON(w, http.StatusOK, list)
}

// handleAddBlacklist bans an IP or CIDR range. duration is optional: empty or
// "permanent" bans for good, otherwise a span like "1h" or "7d" sets a
// temporary ban.
func (s *server) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP       string `json:"ip"`
		Reason   string `json:"reason"`
		Duration string `json:"duration"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	ip := blacklist.NormalizeKey(body.IP)
	if !validBanKey(ip) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address or CIDR range"})
		return
	}
	var dur time.Duration
	if d := strings.TrimSpace(body.Duration); d != "" && d != "permanent" {
		var err error
		if dur, err = parseSpan(d); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
	}
	reason := strings.TrimSpace(body.Reason)
	if reason == "" {
		reason = "manual"
	}
	if s.Blacklist.IsWhitelisted(ip) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "IP is whitelisted"})
		return
	}
	var added bool
	if dur > 0 {
		added = s.Blacklist.AddTemp(ip, reason, dur)
	} else {
		added = s.Blacklist.Add(ip, reason, "")
	}
	if added {
		span := "permanently"
		if dur > 0 {
			span = "for " + strings.TrimSpace(body.Duration)
		}
		s.Activity.Addf(activity.Ban, activity.Info, ip, s.actor(r), "Banned %s from the portal (reason: %s)", span, reason)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "added": added})
}

func (s *server) handleRemoveBlacklist(w http.ResponseWriter, r *http.Request) {
	ip := blacklist.NormalizeKey(r.PathValue("key"))
	removed := s.Blacklist.Remove(ip)
	if removed {
		s.Activity.Addf(activity.Unban, activity.Info, ip, s.actor(r), "Unbanned from the portal")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "removed": removed})
}

func (s *server) handleExportBlacklist(w http.ResponseWriter, r *http.Request) {
	list := s.Blacklist.List()
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	w.Header().Set("Content-Disposition", fmt.Sprintf(
		`attachment; filename="thorngate-blacklist-%s.json"`, time.Now().UTC().Format("20060102")))
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(list)
}

// handleImportBlacklist adds bans in bulk. The body is either a JSON array of
// entries (as exported: ip, reason, optional path/until) or plain text with
// one IP or CIDR per line — the format of most public blocklists — where
// anything after the first field, and lines starting with # or ;, are ignored.
func (s *server) handleImportBlacklist(w http.ResponseWriter, r *http.Request) {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxImportBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "import too large or unreadable"})
		return
	}
	entries, invalid, err := parseImport(data)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	added := s.Blacklist.AddMany(entries)
	s.Activity.Addf(activity.Ban, activity.Info, "", s.actor(r),
		"Imported blacklist: %d added, %d skipped, %d invalid", added, len(entries)-added, len(invalid))
	if len(invalid) > 20 {
		invalid = invalid[:20]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"added":   added,
		"skipped": len(entries) - added, // already banned, whitelisted or expired
		"invalid": invalid,
	})
}

// parseImport turns an import body into ban entries, returning the keys it
// could not parse separately.
func parseImport(data []byte) (entries []blacklist.Entry, invalid []string, err error) {
	data = bytes.TrimSpace(data)
	if bytes.HasPrefix(data, []byte("[")) {
		var list []blacklist.Entry
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, nil, fmt.Errorf("invalid JSON: %v", err)
		}
		for _, e := range list {
			e.IP = blacklist.NormalizeKey(e.IP)
			if !validBanKey(e.IP) {
				invalid = append(invalid, e.IP)
				continue
			}
			if e.Reason == "" {
				e.Reason = "import"
			}
			entries = append(entries, e)
		}
		return entries, invalid, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		key := blacklist.NormalizeKey(strings.Fields(line)[0])
		if !validBanKey(key) {
			invalid = append(invalid, key)
			continue
		}
		entries = append(entries, blacklist.Entry{IP: key, Reason: "import"})
	}
	return entries, invalid, sc.Err()
}

// validBanKey reports whether s is a usable blacklist key: a single IP address
// or a CIDR range.
func validBanKey(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(s)
	return err == nil
}
