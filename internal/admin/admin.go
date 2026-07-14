// Package admin serves the thorngate admin portal: a session-authenticated
// React single-page app (embedded from web/dist via go:embed) plus the JSON API
// it talks to. It is meant to run on a separate, cluster-internal port and must
// never be attached to the tunnel.
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"thorngate/internal/auth"
	"thorngate/internal/blacklist"
	"thorngate/internal/stats"
)

// dist holds the built React portal. It is populated at compile time from
// web/dist, so `go build` needs no Node toolchain — only rebuilding the UI does.
//
//go:embed all:dist
var dist embed.FS

// server bundles the dependencies the handlers close over.
type server struct {
	bl       *blacklist.Blacklist
	st       *stats.Collector
	au       *auth.Store
	apiToken string // optional legacy bearer token for scripted/API access
}

// Handler returns the admin HTTP handler. au drives interactive login; apiToken,
// when non-empty, is an additional bearer token accepted on the API for
// machine access (empty disables it). st may be nil when stats are disabled.
func Handler(bl *blacklist.Blacklist, st *stats.Collector, au *auth.Store, apiToken string) http.Handler {
	s := &server{bl: bl, st: st, au: au, apiToken: apiToken}
	mux := http.NewServeMux()

	// --- Auth ---
	mux.HandleFunc("POST /admin/login", s.handleLogin)
	mux.HandleFunc("POST /admin/logout", s.authed(s.handleLogout))
	mux.HandleFunc("GET /admin/me", s.authed(s.handleMe))
	mux.HandleFunc("POST /admin/password", s.authed(s.handlePassword))

	// --- Data ---
	mux.HandleFunc("GET /admin/stats", s.authed(s.handleStats))
	mux.HandleFunc("GET /admin/stats/recent", s.authed(s.handleRecent))
	mux.HandleFunc("GET /admin/blacklist", s.authed(s.handleListBlacklist))
	mux.HandleFunc("POST /admin/blacklist", s.authed(s.handleAddBlacklist))
	// {key...} is a trailing wildcard so CIDR ranges (which contain "/") can be
	// deleted, e.g. DELETE /admin/blacklist/1.2.3.0/24.
	mux.HandleFunc("DELETE /admin/blacklist/{key...}", s.authed(s.handleRemoveBlacklist))

	// --- Static SPA (everything else) ---
	mux.Handle("/", spaHandler())

	return mux
}

// bearer extracts the token from an Authorization: Bearer <token> header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return after
	}
	return ""
}

// authed wraps a handler with session (or legacy API token) authentication.
func (s *server) authed(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if s.au.Valid(tok) ||
			(s.apiToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.apiToken)) == 1) {
			next(w, r)
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	token, err := s.au.Login(strings.TrimSpace(body.Username), body.Password)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "username": s.au.Username()})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.au.Logout(bearer(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"username": s.au.Username()})
}

func (s *server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	switch err := s.au.ChangePassword(body.Current, body.New); err {
	case nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case auth.ErrBadCredentials:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "current password is incorrect"})
	case auth.ErrWeakPassword:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password is too short"})
	default:
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not change password"})
	}
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "stats": s.st.Snapshot()})
}

// recentWindow is how far back the paginated recent-requests feed reaches.
const recentWindow = 24 * time.Hour

// maxRecentPageSize caps page_size so a single request can't dump the whole feed.
const maxRecentPageSize = 200

func (s *server) handleRecent(w http.ResponseWriter, r *http.Request) {
	if s.st == nil {
		writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	if size > maxRecentPageSize {
		size = maxRecentPageSize
	}
	writeJSON(w, http.StatusOK, struct {
		Enabled bool `json:"enabled"`
		stats.RecentPage
	}{true, s.st.Recent(recentWindow, page, size)})
}

func (s *server) handleListBlacklist(w http.ResponseWriter, r *http.Request) {
	list := s.bl.List()
	sort.Slice(list, func(i, j int) bool { return list[i].Timestamp.After(list[j].Timestamp) })
	writeJSON(w, http.StatusOK, list)
}

func (s *server) handleAddBlacklist(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP     string `json:"ip"`
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	ip := strings.TrimSpace(body.IP)
	if !validBanKey(ip) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address or CIDR range"})
		return
	}
	reason := body.Reason
	if reason == "" {
		reason = "manual"
	}
	if s.bl.IsWhitelisted(ip) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "IP is whitelisted"})
		return
	}
	added := s.bl.Add(ip, reason, "")
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "added": added})
}

func (s *server) handleRemoveBlacklist(w http.ResponseWriter, r *http.Request) {
	ip := r.PathValue("key")
	removed := s.bl.Remove(ip)
	writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "removed": removed})
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

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// spaHandler serves the embedded React build, falling back to index.html for
// any path that isn't a real asset so client-side routing works.
func spaHandler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		panic("admin: embedded dist missing: " + err.Error())
	}
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		panic("admin: embedded dist/index.html missing: " + err.Error())
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if clean == "." || clean == "" {
			serveIndex(w, index)
			return
		}
		if f, err := sub.Open(clean); err == nil {
			_ = f.Close()
			files.ServeHTTP(w, r)
			return
		}
		serveIndex(w, index)
	})
}

func serveIndex(w http.ResponseWriter, index []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(index)
}
