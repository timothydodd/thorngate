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
- **`internal/blacklist`** — thread-safe store with atomic file persistence (temp file + fsync + rename). Two backing structures: exact IPs in a map (O(1)), CIDR ranges in a slice matched by `net.Contains`. A key containing `/` is treated as a CIDR. Temp vs permanent reconciliation matters: a permanent ban outranks/upgrades a temporary one, and whitelisted IPs are never blocked even inside a banned range. CIDR bans are **manual only** (admin API / config) — honeypots and temp-bans only ever ban single IPs.
- **`internal/monitor`** — per-IP sliding-window strike counter backing temp-bans. Swept periodically.
- **`internal/history`** — bounded in-memory ring buffer (per-IP `depth` × `max_ips`, TTL-swept) of recent requests, dumped to the log when an IP is blacklisted. Memory-only, never persisted.
- **`internal/admin`** — optional token-protected API + self-contained web page on a **separate port**, for live blacklist management. Never attach this port to the tunnel.

### Conventions worth preserving

- **Zero-overhead-when-off**: temp-ban and request-log features wrap the response (`statusWriter`) only when enabled — `ServeHTTP` proxies directly otherwise. Preserve this fast path when adding response-inspecting features.
- **`statusWriter`** wraps `http.ResponseWriter` to capture the status code; it must forward `Flush` (streaming) and `Hijack` (WebSocket/SignalR protocol upgrades — hijacked connections record a `101`). Adding a new response feature usually means touching this wrapper.
- `/healthz` is reserved (registered separately in `main.go`) — never proxied, never honeypot-able.
- Mutating-store methods (`Add`/`Remove`) snapshot under lock then `persist` outside it. Follow that pattern to avoid holding the lock during disk I/O.

The README is thorough and user-facing — consult it for config-field semantics and deployment (k3s manifests in `deploy/k3s/`, cloudflared ingress). When you change behavior of a config field, honeypot match mode, or the admin API, update the README too.
