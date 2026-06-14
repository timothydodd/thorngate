// Package admin serves a small token-protected API and web page for managing
// the blacklist. It is meant to run on a separate, cluster-internal port.
package admin

import (
	"crypto/subtle"
	"encoding/json"
	"net"
	"net/http"
	"sort"
	"strings"

	"thorngate/internal/blacklist"
)

// Handler returns the admin HTTP handler. token is required as a bearer token
// on every API call; the HTML page itself is served unauthenticated (it carries
// no data and asks for the token in-page).
func Handler(bl *blacklist.Blacklist, token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", servePage)
	mux.HandleFunc("GET /admin/{$}", servePage)
	mux.Handle("GET /admin/blacklist", auth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		list := bl.List()
		sort.Slice(list, func(i, j int) bool { return list[i].Timestamp.After(list[j].Timestamp) })
		writeJSON(w, http.StatusOK, list)
	})))
	mux.Handle("POST /admin/blacklist", auth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}
		ip := strings.TrimSpace(body.IP)
		if net.ParseIP(ip) == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address"})
			return
		}
		reason := body.Reason
		if reason == "" {
			reason = "manual"
		}
		if bl.IsWhitelisted(ip) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "IP is whitelisted"})
			return
		}
		added := bl.Add(ip, reason, "")
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "added": added})
	})))
	mux.Handle("DELETE /admin/blacklist/{ip}", auth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("ip")
		removed := bl.Remove(ip)
		writeJSON(w, http.StatusOK, map[string]any{"ip": ip, "removed": removed})
	})))

	return mux
}

// auth enforces a constant-time bearer-token check.
func auth(token string, next http.Handler) http.Handler {
	want := "Bearer " + token
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func servePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>thorngate · blacklist</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 820px; margin: 2rem auto; padding: 0 1rem; }
  h1 { font-size: 1.3rem; }
  input { font: inherit; padding: .4rem .5rem; border: 1px solid #8888; border-radius: 6px; }
  button { font: inherit; padding: .4rem .7rem; border: 0; border-radius: 6px; background: #2563eb; color: #fff; cursor: pointer; }
  button.danger { background: #dc2626; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th, td { text-align: left; padding: .5rem .4rem; border-bottom: 1px solid #8883; font-size: .92rem; }
  .row { display: flex; gap: .5rem; flex-wrap: wrap; align-items: center; margin: .6rem 0; }
  .muted { color: #888; }
  .tag { font-size: .8rem; padding: .1rem .4rem; border-radius: 4px; background: #8882; }
  #msg { min-height: 1.2rem; }
</style>
</head>
<body>
<h1>thorngate · blacklist</h1>
<div class="row">
  <input id="token" type="password" placeholder="admin token" style="flex:1; min-width:220px">
  <button onclick="saveToken()">Save token</button>
  <button onclick="load()">Refresh</button>
</div>
<div class="row">
  <input id="ip" placeholder="IP to ban (e.g. 1.2.3.4)" style="flex:1; min-width:220px">
  <input id="reason" placeholder="reason (optional)">
  <button onclick="add()">Ban</button>
</div>
<div id="msg" class="muted"></div>
<table>
  <thead><tr><th>IP</th><th>reason</th><th>expires</th><th>added</th><th></th></tr></thead>
  <tbody id="rows"></tbody>
</table>
<script>
function tok() { return localStorage.getItem('tg_token') || ''; }
function saveToken() { localStorage.setItem('tg_token', document.getElementById('token').value); msg('token saved'); load(); }
function msg(t, err) { const m = document.getElementById('msg'); m.textContent = t; m.style.color = err ? '#dc2626' : '#888'; }
function hdr() { return { 'Authorization': 'Bearer ' + tok(), 'Content-Type': 'application/json' }; }

async function load() {
  try {
    const res = await fetch('/admin/blacklist', { headers: hdr() });
    if (!res.ok) { msg('load failed: ' + res.status + (res.status === 401 ? ' (check token)' : ''), true); return; }
    const list = await res.json();
    const rows = document.getElementById('rows');
    rows.innerHTML = '';
    if (!list.length) { msg('no blacklisted IPs'); }
    else { msg(list.length + ' blacklisted'); }
    for (const e of list) {
      const tr = document.createElement('tr');
      const until = e.until ? new Date(e.until).toLocaleString() : '<span class="tag">permanent</span>';
      tr.innerHTML =
        '<td>' + e.ip + '</td>' +
        '<td>' + (e.reason || '') + '</td>' +
        '<td>' + until + '</td>' +
        '<td class="muted">' + new Date(e.timestamp).toLocaleString() + '</td>' +
        '<td></td>';
      const btn = document.createElement('button');
      btn.className = 'danger'; btn.textContent = 'Unban';
      btn.onclick = () => remove(e.ip);
      tr.lastElementChild.appendChild(btn);
      rows.appendChild(tr);
    }
  } catch (err) { msg('error: ' + err, true); }
}

async function add() {
  const ip = document.getElementById('ip').value.trim();
  const reason = document.getElementById('reason').value.trim();
  const res = await fetch('/admin/blacklist', { method: 'POST', headers: hdr(), body: JSON.stringify({ ip, reason }) });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) { msg(j.error || ('failed: ' + res.status), true); return; }
  document.getElementById('ip').value = ''; document.getElementById('reason').value = '';
  load();
}

async function remove(ip) {
  const res = await fetch('/admin/blacklist/' + encodeURIComponent(ip), { method: 'DELETE', headers: hdr() });
  if (!res.ok) { msg('remove failed: ' + res.status, true); return; }
  load();
}

document.getElementById('token').value = tok();
load();
</script>
</body>
</html>`
