# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

thorngate is a tiny, **standard-library-only** Go reverse-proxy WAF. It sits behind a Cloudflare Tunnel and in front of internal web/API services: it reverse-proxies traffic to upstreams, instantly blacklists any IP that hits a configured honeypot path, optionally temp-bans IPs that produce too many bad responses, and persists the blacklist to disk. There are **no third-party dependencies** — `go.mod` lists only the module and Go version, so `go build` works offline. Keep it that way unless there's a strong reason not to.

## Commands

```bash
go build -o thorngate ./cmd/thorngate   # build the binary
./thorngate -config config.json         # run (default listen :8765)
go test ./...                           # run all tests
go test ./internal/blacklist/           # test one package
go test -run TestAddCIDR ./internal/blacklist/   # run a single test
go vet ./...                            # vet (part of CI)
```

CI (`.github/workflows/ci.yml`) runs `go vet`, `go build`, and `go test` over `./...` on every push/PR. `release.yml` builds a multi-arch GHCR image on a `vX.Y.Z` tag. Tests are table-driven and live alongside each package (`*_test.go`); most logic is unit-tested without a live server, so prefer adding to those rather than spinning up the proxy.

Note: the user develops on Windows and runs Docker/release builds there — don't assume a failed container build is a code problem.

## Architecture

The whole request lifecycle lives in `internal/proxy/proxy.go` (`WAF.ServeHTTP`), wired up in `cmd/thorngate/main.go`. Read those two files first. The flow, in order:

1. **Resolve client IP** (`clientIP`) — from the configured header (`Cf-Connecting-Ip`), falling back to the TCP peer. This trust of a header is *the* security assumption: it only holds because the Service is ClusterIP-only and reachable solely by in-cluster `cloudflared`. Don't break that assumption.
2. **Blacklist check** (`blacklist.IsBlocked`) → `403`, no upstream contact.
3. **Honeypot check** (`config.Honeypot.Matches`) → permanent ban + `403`.
4. **Route + proxy** (`upstreamFor`) — host-based override or the default upstream.
5. **Post-response** — record history and apply temp-ban strikes (only when those features are on).

### Package responsibilities

- **`internal/config`** — JSON config loading and all matcher logic. `Honeypot` has a custom `UnmarshalJSON` so a honeypot is either a bare string (prefix match) or an object with a `match` mode (`prefix`/`contains`/`suffix`/`glob`/`regex`); patterns are **compiled once at load time** (`compile()`), not per request. `TempBan`/`RequestLog` likewise parse durations and pre-build lookup sets in `compile()`. `ParseUpstream` normalizes IP/`host:port`/URL forms (scheme defaults to `http`).
- **`internal/blacklist`** — thread-safe store with atomic file persistence (temp file + fsync + rename). Two backing structures: exact IPs in a map (O(1)), and CIDR ranges grouped by prefix length (`map[maskShape]map[network]Entry`), so a lookup is one map probe per distinct prefix length. A key containing `/` is a CIDR; keys are canonicalized by `NormalizeKey`. Temp vs permanent reconciliation matters: a permanent ban outranks/upgrades a temporary one, and whitelisted IPs are never blocked even inside a banned range. Automatic bans of **IPv6** clients cover their `/ipv6_ban_prefix` (default /64) via `BanKey`; IPv4 automatic bans are always single IPs. `AddMany` applies a batch (imports) with one disk write. The whitelist is an `atomic.Pointer` so config reload can swap it.
- **`internal/archive`** — optional on-disk request history (`stats.archive`). One writer goroutine appends JSON lines to an hourly segment via a non-blocking queue (drops are counted, never block the proxy); when the hour closes the segment is gzipped and an index (totals, per-IP and per-path counts) is written. Queries read indexes first and only open the hours that matter. Implements `stats.History`. Sealing takes `segMu` because renaming/removing files that a reader has open fails on Windows (where tests run).
- **`internal/monitor`** — sliding-window strike counter backing temp-bans (keyed by ban key, so an IPv6 /64 counts as one client) and temp-ban escalation. Swept periodically.
- **`internal/stats`** — lock-free counters + per-minute ring for the dashboard, the in-memory recent-requests feed, and the history query layer (`History` interface, `Filter`, `Summarizer`). The collector implements `History` over its feed; the admin API prefers the archive when configured.
- **`internal/history`** — bounded in-memory ring buffer (per-IP `depth` × `max_ips`, TTL-swept) of recent requests, dumped to the log when an IP is blacklisted. Memory-only, never persisted.
- **`internal/admin`** — optional login-protected admin portal on a **separate port**: the JSON API plus a **React SPA embedded via `go:embed` from `internal/admin/dist`** (built from `web/` — run `npm run build` there to refresh it; `go build` needs no Node because `dist` is committed). Never attach this port to the tunnel. Auth is session-based (see `internal/auth`); a legacy static `admin.token` is still accepted for scripted access. `admin.Handler` takes an `Options` struct; handlers are split across `admin.go` (auth/SPA), `traffic.go` (history endpoints), `banlist.go` (blacklist/import/export) and `metrics.go` (Prometheus, unauthenticated). Sessions are locked to password-change only while `auth.Store.MustChange()` is true.
- **`internal/auth`** — admin credential store: one username + salted **PBKDF2-HMAC-SHA256** password hash, persisted atomically (same temp-file+fsync+rename pattern as the blacklist), plus in-memory session tokens. Seeds **admin/admin** on a fresh install. PBKDF2 is hand-implemented (stdlib `crypto/hmac`+`crypto/sha256`) because `crypto/pbkdf2` postdates this module's Go 1.22 target — keep it stdlib-only.

### Conventions worth preserving

- **Zero-overhead-when-off**: temp-ban and request-log features wrap the response (`statusWriter`) only when enabled — `ServeHTTP` proxies directly otherwise. Preserve this fast path when adding response-inspecting features.
- **`statusWriter`** wraps `http.ResponseWriter` to capture the status code; it must forward `Flush` (streaming) and `Hijack` (WebSocket/SignalR protocol upgrades — hijacked connections record a `101`). Adding a new response feature usually means touching this wrapper.
- `/healthz` is reserved (handled in `main.go`'s top-level handler, which is deliberately not an `http.ServeMux` — its unclean-path 301s would answer blacklisted clients) — never proxied, never honeypot-able.
- **Live reload**: settings read on the request path live in `proxy.rules` behind an `atomic.Pointer`; `ServeHTTP` loads it once per request. Anything a reload can change must be read from there, not captured at `New`. `config.ReloadBlocked` lists the settings that need a restart.
- **Config parsing is strict** (`DisallowUnknownFields`). Custom `UnmarshalJSON` methods must call `strictUnmarshal` themselves or unknown keys inside them slip through.
- Mutating-store methods (`Add`/`Remove`/`Sweep`) snapshot under lock via `changedLocked()` (which bumps a generation counter) then `persist` outside it. `persist` serializes writes and skips snapshots older than one already on disk — concurrent writers share one `.tmp` file, so never write it without that guard. Follow that pattern to avoid holding the lock during disk I/O.

The README is thorough and user-facing — consult it for config-field semantics and deployment (k3s manifests in `deploy/k3s/`, cloudflared ingress). When you change behavior of a config field, honeypot match mode, or the admin API, update the README too.
