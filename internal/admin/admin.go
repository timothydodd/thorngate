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
	"thorngate/internal/stats"
)

// Handler returns the admin HTTP handler. token is required as a bearer token
// on every API call; the HTML page itself is served unauthenticated (it carries
// no data and asks for the token in-page). st may be nil when stats are
// disabled, in which case the stats endpoint reports the feature as off.
func Handler(bl *blacklist.Blacklist, st *stats.Collector, token string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", servePage)
	mux.HandleFunc("GET /admin/{$}", servePage)
	mux.Handle("GET /admin/stats", auth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st == nil {
			writeJSON(w, http.StatusOK, map[string]any{"enabled": false})
			return
		}
		snap := st.Snapshot()
		writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "stats": snap})
	})))
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
		if !validBanKey(ip) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid IP address or CIDR range"})
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
	// {key...} is a trailing wildcard so CIDR ranges (which contain a "/") can be
	// deleted, e.g. DELETE /admin/blacklist/1.2.3.0/24.
	mux.Handle("DELETE /admin/blacklist/{key...}", auth(token, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.PathValue("key")
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

func servePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(page))
}

const page = `<!doctype html>
<html lang="en" class="h-full">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>thorngate</title>
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = { darkMode: 'media', theme: { extend: { fontFamily: { sans: ['ui-sans-serif','system-ui','sans-serif'] } } } };
</script>
</head>
<body class="h-full bg-slate-50 text-slate-800 dark:bg-slate-950 dark:text-slate-200">
<div class="max-w-5xl mx-auto px-4 py-8">

  <header class="flex flex-wrap items-center justify-between gap-3 mb-6">
    <h1 class="text-2xl font-semibold tracking-tight flex items-center gap-2">
      <span class="inline-block w-2.5 h-2.5 rounded-full bg-emerald-500"></span>thorngate
    </h1>
    <div class="flex items-center gap-2">
      <input id="token" type="password" placeholder="admin token"
        class="px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm w-48">
      <button onclick="saveToken()"
        class="px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium">Save token</button>
      <button onclick="refresh()"
        class="px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 text-sm">Refresh</button>
    </div>
  </header>

  <nav class="flex gap-1 mb-6 border-b border-slate-200 dark:border-slate-800">
    <button data-tab="stats" onclick="showTab('stats')"
      class="tab px-4 py-2 text-sm font-medium border-b-2 border-blue-600 text-blue-600">Dashboard</button>
    <button data-tab="blacklist" onclick="showTab('blacklist')"
      class="tab px-4 py-2 text-sm font-medium border-b-2 border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200">Blacklist</button>
  </nav>

  <div id="msg" class="text-sm text-slate-500 min-h-[1.25rem] mb-4"></div>

  <!-- Dashboard tab -->
  <section id="tab-stats">
    <div id="stats-cards" class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3 mb-6"></div>
    <div class="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">
      <div class="flex items-center justify-between mb-3">
        <h2 class="text-sm font-semibold text-slate-600 dark:text-slate-300">Traffic (requests / min)</h2>
        <div class="flex items-center gap-3 text-xs text-slate-500">
          <span class="flex items-center gap-1"><span class="inline-block w-3 h-1.5 rounded bg-blue-500"></span>requests</span>
          <span class="flex items-center gap-1"><span class="inline-block w-3 h-1.5 rounded bg-rose-500"></span>blocked</span>
        </div>
      </div>
      <canvas id="chart" height="160" class="w-full"></canvas>
    </div>
    <p id="stats-since" class="text-xs text-slate-400 mt-3"></p>

    <div class="mt-6 rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
      <div class="px-4 py-2.5 bg-slate-100 dark:bg-slate-800/60 flex items-center justify-between">
        <h2 class="text-sm font-semibold text-slate-600 dark:text-slate-300">Recent requests</h2>
        <span id="recent-count" class="text-xs text-slate-400"></span>
      </div>
      <div class="max-h-96 overflow-auto">
        <table class="w-full text-sm">
          <thead class="bg-slate-50 dark:bg-slate-900/60 text-slate-500 text-xs uppercase tracking-wide sticky top-0">
            <tr><th class="text-left font-medium px-4 py-2">Time</th><th class="text-left font-medium px-4 py-2">IP</th>
            <th class="text-left font-medium px-4 py-2">Method</th><th class="text-left font-medium px-4 py-2">Path</th>
            <th class="text-left font-medium px-4 py-2">Status</th><th class="text-left font-medium px-4 py-2">Outcome</th></tr>
          </thead>
          <tbody id="recent-rows" class="divide-y divide-slate-100 dark:divide-slate-800"></tbody>
        </table>
      </div>
    </div>
  </section>

  <!-- Blacklist tab -->
  <section id="tab-blacklist" class="hidden">
    <div class="flex flex-wrap items-center gap-2 mb-4">
      <input id="ip" placeholder="IP or CIDR to ban (e.g. 1.2.3.4 or 1.2.3.0/24)"
        class="flex-1 min-w-[240px] px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm">
      <input id="reason" placeholder="reason (optional)"
        class="px-3 py-1.5 rounded-md border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-900 text-sm">
      <button onclick="add()" class="px-3 py-1.5 rounded-md bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium">Ban</button>
    </div>
    <div class="rounded-xl border border-slate-200 dark:border-slate-800 overflow-hidden">
      <table class="w-full text-sm">
        <thead class="bg-slate-100 dark:bg-slate-800/60 text-slate-500 text-xs uppercase tracking-wide">
          <tr><th class="text-left font-medium px-4 py-2">IP</th><th class="text-left font-medium px-4 py-2">Reason</th>
          <th class="text-left font-medium px-4 py-2">Expires</th><th class="text-left font-medium px-4 py-2">Added</th><th class="px-4 py-2"></th></tr>
        </thead>
        <tbody id="rows" class="divide-y divide-slate-100 dark:divide-slate-800"></tbody>
      </table>
    </div>
  </section>

</div>
<script>
function tok() { return localStorage.getItem('tg_token') || ''; }
function saveToken() { localStorage.setItem('tg_token', document.getElementById('token').value); msg('token saved'); refresh(); }
function msg(t, err) { const m = document.getElementById('msg'); m.textContent = t; m.className = 'text-sm min-h-[1.25rem] mb-4 ' + (err ? 'text-rose-500' : 'text-slate-500'); }
function hdr() { return { 'Authorization': 'Bearer ' + tok(), 'Content-Type': 'application/json' }; }

let activeTab = 'stats';
function showTab(name) {
  activeTab = name;
  for (const el of document.querySelectorAll('.tab')) {
    const on = el.dataset.tab === name;
    el.className = 'tab px-4 py-2 text-sm font-medium border-b-2 ' +
      (on ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200');
  }
  document.getElementById('tab-stats').classList.toggle('hidden', name !== 'stats');
  document.getElementById('tab-blacklist').classList.toggle('hidden', name !== 'blacklist');
  refresh();
}

function refresh() { if (activeTab === 'stats') loadStats(); else loadBlacklist(); }

function card(label, value, accent) {
  return '<div class="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4">' +
    '<div class="text-2xl font-semibold ' + (accent || '') + '">' + value.toLocaleString() + '</div>' +
    '<div class="text-xs text-slate-500 mt-1">' + label + '</div></div>';
}

async function loadStats() {
  try {
    const res = await fetch('/admin/stats', { headers: hdr() });
    if (!res.ok) { msg('load failed: ' + res.status + (res.status === 401 ? ' (check token)' : ''), true); return; }
    const j = await res.json();
    if (!j.enabled) { document.getElementById('stats-cards').innerHTML = ''; msg('stats are disabled in config', true); return; }
    const s = j.stats;
    msg('');
    document.getElementById('stats-cards').innerHTML =
      card('Total requests', s.requests) +
      card('Blocked (blacklist)', s.blocked, 'text-rose-500') +
      card('Honeypot bans', s.honeypots, 'text-amber-500') +
      card('Temp bans', s.temp_bans, 'text-amber-500') +
      card('2xx', s.status_2xx, 'text-emerald-500') +
      card('3xx', s.status_3xx, 'text-sky-500') +
      card('4xx', s.status_4xx, 'text-amber-500') +
      card('5xx', s.status_5xx, 'text-rose-500');
    document.getElementById('stats-since').textContent = 'counting since ' + new Date(s.since).toLocaleString();
    drawChart(s.series || []);
    renderRecent(s.recent || []);
  } catch (err) { msg('error: ' + err, true); }
}

function esc(t) { const d = document.createElement('div'); d.textContent = t == null ? '' : t; return d.innerHTML; }

function outcomeBadge(o) {
  const map = {
    blocked: 'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300',
    honeypot: 'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
    proxied: 'bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300',
  };
  return '<span class="text-xs px-1.5 py-0.5 rounded ' + (map[o] || map.proxied) + '">' + esc(o) + '</span>';
}

function statusColor(code) {
  if (code >= 500) return 'text-rose-500';
  if (code >= 400) return 'text-amber-500';
  if (code >= 300) return 'text-sky-500';
  return 'text-emerald-500';
}

function renderRecent(list) {
  document.getElementById('recent-count').textContent = list.length ? list.length + ' shown (newest first)' : '';
  const rows = document.getElementById('recent-rows');
  if (!list.length) { rows.innerHTML = '<tr><td colspan="6" class="px-4 py-3 text-slate-400">no requests yet</td></tr>'; return; }
  rows.innerHTML = list.map(e =>
    '<tr>' +
    '<td class="px-4 py-1.5 text-slate-400 whitespace-nowrap">' + new Date(e.time).toLocaleTimeString() + '</td>' +
    '<td class="px-4 py-1.5 font-mono whitespace-nowrap">' + esc(e.ip) + '</td>' +
    '<td class="px-4 py-1.5">' + esc(e.method) + '</td>' +
    '<td class="px-4 py-1.5 font-mono max-w-xs truncate" title="' + esc(e.path) + '">' + esc(e.path) + '</td>' +
    '<td class="px-4 py-1.5 font-mono ' + statusColor(e.status) + '">' + e.status + '</td>' +
    '<td class="px-4 py-1.5">' + outcomeBadge(e.outcome) + '</td>' +
    '</tr>'
  ).join('');
}

function drawChart(series) {
  const cv = document.getElementById('chart');
  const dpr = window.devicePixelRatio || 1;
  const w = cv.clientWidth, h = 160;
  cv.width = w * dpr; cv.height = h * dpr;
  const ctx = cv.getContext('2d'); ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  if (!series.length) return;
  const max = Math.max(1, ...series.map(b => b.requests));
  const pad = 24, plotH = h - pad, plotW = w;
  const x = i => series.length === 1 ? plotW / 2 : (i / (series.length - 1)) * plotW;
  const y = v => plotH - (v / max) * (plotH - 6) + 3;
  // gridline + max label
  ctx.strokeStyle = 'rgba(148,163,184,.25)'; ctx.beginPath(); ctx.moveTo(0, y(max)); ctx.lineTo(w, y(max)); ctx.stroke();
  ctx.fillStyle = 'rgba(148,163,184,.9)'; ctx.font = '11px system-ui'; ctx.fillText(max + '/min', 2, y(max) - 4);
  const line = (key, color) => {
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    series.forEach((b, i) => { const px = x(i), py = y(b[key]); i ? ctx.lineTo(px, py) : ctx.moveTo(px, py); });
    ctx.stroke();
  };
  line('requests', '#3b82f6');
  line('blocked', '#f43f5e');
  // time axis labels (oldest / newest)
  ctx.fillStyle = 'rgba(148,163,184,.9)';
  const fmt = t => new Date(t * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  ctx.fillText(fmt(series[0].t), 0, h - 4);
  const last = fmt(series[series.length - 1].t); ctx.fillText(last, w - ctx.measureText(last).width, h - 4);
}

async function loadBlacklist() {
  try {
    const res = await fetch('/admin/blacklist', { headers: hdr() });
    if (!res.ok) { msg('load failed: ' + res.status + (res.status === 401 ? ' (check token)' : ''), true); return; }
    const list = await res.json();
    const rows = document.getElementById('rows');
    rows.innerHTML = '';
    msg(list.length ? list.length + ' blacklisted' : 'no blacklisted IPs');
    for (const e of list) {
      const tr = document.createElement('tr');
      const until = e.until
        ? new Date(e.until).toLocaleString()
        : '<span class="text-xs px-1.5 py-0.5 rounded bg-slate-200 dark:bg-slate-700">permanent</span>';
      tr.innerHTML =
        '<td class="px-4 py-2 font-mono">' + e.ip + '</td>' +
        '<td class="px-4 py-2">' + (e.reason || '') + '</td>' +
        '<td class="px-4 py-2">' + until + '</td>' +
        '<td class="px-4 py-2 text-slate-400">' + new Date(e.timestamp).toLocaleString() + '</td>' +
        '<td class="px-4 py-2 text-right"></td>';
      const btn = document.createElement('button');
      btn.className = 'px-2.5 py-1 rounded-md bg-rose-600 hover:bg-rose-500 text-white text-xs';
      btn.textContent = 'Unban';
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
  loadBlacklist();
}

async function remove(ip) {
  const res = await fetch('/admin/blacklist/' + encodeURIComponent(ip), { method: 'DELETE', headers: hdr() });
  if (!res.ok) { msg('remove failed: ' + res.status, true); return; }
  loadBlacklist();
}

document.getElementById('token').value = tok();
window.addEventListener('resize', () => { if (activeTab === 'stats') loadStats(); });
setInterval(refresh, 10000); // live refresh every 10s
refresh();
</script>
</body>
</html>`
