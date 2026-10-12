// Package admin serves the thorngate admin portal: a session-authenticated
// React single-page app (embedded from web/dist via go:embed) plus the JSON API
// it talks to. It is meant to run on a separate, cluster-internal port and must
// never be attached to the tunnel.
package admin

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"thorngate/internal/archive"
	"thorngate/internal/auth"
	"thorngate/internal/blacklist"
	"thorngate/internal/config"
	"thorngate/internal/feeds"
	"thorngate/internal/stats"
)

// dist holds the built React portal. It is populated at compile time from
// web/dist, so `go build` needs no Node toolchain — only rebuilding the UI does.
//
//go:embed all:dist
var dist embed.FS

// Options wires the admin portal to the running WAF.
type Options struct {
	Blacklist *blacklist.Blacklist
	Stats     *stats.Collector // nil when stats are disabled
	Archive   *archive.Archive // nil unless stats.archive is configured
	Auth      *auth.Store
	// APIToken, when non-empty, is a bearer token accepted on the API for
	// machine access alongside session logins.
	APIToken string
	// Whitelist returns the current whitelist (it changes on reload).
	Whitelist func() []config.WhitelistEntry
	// WhitelistFeeds returns each whitelist feed's ranges and fetch status.
	WhitelistFeeds func() []feeds.Status
	// Reload re-reads the config file and applies what it can live, returning
	// the changed settings that still need a restart. Nil disables reloading.
	Reload func() (restartRequired []string, err error)
	// Tarpitting reports connections currently held by the tarpit (metrics).
	Tarpitting func() int64
	// Metrics serves Prometheus text metrics at /metrics, unauthenticated.
	Metrics bool
}

// server bundles the dependencies the handlers close over.
type server struct {
	Options
}

// Handler returns the admin HTTP handler.
func Handler(o Options) http.Handler {
	s := &server{Options: o}
	mux := http.NewServeMux()

	// --- Auth --- (usable while a password change is pending)
	mux.HandleFunc("POST /admin/login", s.handleLogin)
	mux.HandleFunc("POST /admin/logout", s.authedAny(s.handleLogout))
	mux.HandleFunc("GET /admin/me", s.authedAny(s.handleMe))
	mux.HandleFunc("POST /admin/password", s.authedAny(s.handlePassword))

	// --- Traffic ---
	mux.HandleFunc("GET /admin/stats", s.authed(s.handleStats))
	mux.HandleFunc("GET /admin/requests", s.authed(s.handleRequests))
	mux.HandleFunc("GET /admin/stats/recent", s.authed(s.handleRequests)) // older name
	mux.HandleFunc("GET /admin/top", s.authed(s.handleTop))
	mux.HandleFunc("GET /admin/hourly", s.authed(s.handleHourly))
	mux.HandleFunc("GET /admin/ip/{ip}", s.authed(s.handleIP))

	// --- Blacklist / whitelist / config ---
	mux.HandleFunc("GET /admin/blacklist", s.authed(s.handleListBlacklist))
	mux.HandleFunc("POST /admin/blacklist", s.authed(s.handleAddBlacklist))
	mux.HandleFunc("GET /admin/blacklist/export", s.authed(s.handleExportBlacklist))
	mux.HandleFunc("POST /admin/blacklist/import", s.authed(s.handleImportBlacklist))
	// {key...} is a trailing wildcard so CIDR ranges (which contain "/") can be
	// deleted, e.g. DELETE /admin/blacklist/1.2.3.0/24.
	mux.HandleFunc("DELETE /admin/blacklist/{key...}", s.authed(s.handleRemoveBlacklist))
	mux.HandleFunc("GET /admin/whitelist", s.authed(s.handleWhitelist))
	mux.HandleFunc("GET /admin/whitelist/feeds", s.authed(s.handleWhitelistFeeds))
	mux.HandleFunc("POST /admin/reload", s.authed(s.handleReload))

	if o.Metrics {
		mux.HandleFunc("GET /metrics", s.handleMetrics)
	}

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

// authed wraps a handler with session (or API token) authentication. While
// the admin password is still the seeded default, sessions are refused with
// must_change so the portal forces a password change first. The API token is
// unaffected: it was configured deliberately.
func (s *server) authed(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(next, true)
}

// authedAny is authed without the pending-password-change gate, for the few
// endpoints needed to perform the change.
func (s *server) authedAny(next http.HandlerFunc) http.HandlerFunc {
	return s.auth(next, false)
}

func (s *server) auth(next http.HandlerFunc, gate bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if s.APIToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.APIToken)) == 1 {
			next(w, r)
			return
		}
		if !s.Auth.Valid(tok) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if gate && s.Auth.MustChange() {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error": "change the default password first", "must_change": true})
			return
		}
		next(w, r)
	}
}

// maxBodyBytes caps JSON request bodies; every admin payload but an import is
// tiny.
const maxBodyBytes = 64 << 10

// decodeJSON reads a size-capped JSON body into v, writing a 400 on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	token, err := s.Auth.Login(strings.TrimSpace(body.Username), body.Password)
	if errors.Is(err, auth.ErrLockedOut) {
		wait := s.Auth.LockedFor()
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": fmt.Sprintf("too many failed logins; try again in %s", wait.Round(time.Second))})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "username": s.Auth.Username(), "must_change": s.Auth.MustChange()})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.Auth.Logout(bearer(r))
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"username": s.Auth.Username(), "must_change": s.Auth.MustChange()})
}

func (s *server) handlePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	switch err := s.Auth.ChangePassword(body.Current, body.New, bearer(r)); err {
	case nil:
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	case auth.ErrBadCredentials:
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "current password is incorrect"})
	case auth.ErrWeakPassword:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": fmt.Sprintf(
			"new password must be at least %d characters and differ from the current and default passwords",
			auth.MinPasswordLen)})
	default:
		log.Printf("admin: password change failed: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not save new password (is the credentials file writable?)"})
	}
}

func (s *server) handleWhitelist(w http.ResponseWriter, r *http.Request) {
	list := []config.WhitelistEntry{}
	if s.Whitelist != nil {
		list = append(list, s.Whitelist()...)
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) handleWhitelistFeeds(w http.ResponseWriter, r *http.Request) {
	list := []feeds.Status{}
	if s.WhitelistFeeds != nil {
		list = append(list, s.WhitelistFeeds()...)
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *server) handleReload(w http.ResponseWriter, r *http.Request) {
	if s.Reload == nil {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "config reload is not available"})
		return
	}
	restart, err := s.Reload()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "config not reloaded: " + err.Error()})
		return
	}
	if restart == nil {
		restart = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "restart_required": restart})
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
