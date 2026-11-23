# Security Policy

thorngate is a reverse-proxy WAF, so security bugs in it can expose the
services it protects. Reports are welcome and taken seriously.

## Supported versions

Only the latest tagged release (`vX.Y.Z` on GitHub, `ghcr.io` image with the
same tag) receives security fixes. Please upgrade before reporting.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via GitHub's
[private vulnerability reporting](https://github.com/timothydodd/thorngate/security/advisories/new)
on this repository. Include:

- A description of the issue and its impact (what an attacker gains).
- Steps or a minimal config/request sequence to reproduce it.
- The version (`thorngate -version`) or commit you tested against.

You should get an acknowledgement within 7 days. Confirmed issues are fixed
in a new tagged release and disclosed via a GitHub security advisory once a
fix is available. Credit is given to reporters unless they prefer otherwise.

## Scope

In scope:

- Bypassing the blacklist, honeypot, block-rule, or temp-ban checks so a
  request that should be denied reaches an upstream.
- Authentication or session flaws in the admin portal / admin API, or
  privilege escalation via the legacy `admin.token`.
- Request smuggling, header injection, or path handling that lets a client
  reach `/healthz`, an unintended upstream, or the admin port through the
  proxy port.
- Denial of service that a single unauthenticated client can trigger with
  modest traffic (e.g. unbounded memory from a crafted request).
- Unsafe file handling in blacklist/auth/archive persistence (path traversal,
  symlink following, world-readable secrets).

Out of scope, by design (see the README "Security notes"):

- Spoofing `Cf-Connecting-Ip` when thorngate is reachable directly. The
  header is trusted on purpose; the deployment must keep the Service
  `ClusterIP`-only so that only in-cluster `cloudflared` can reach it.
- Exposing the admin port to the internet or attaching it to the tunnel. It
  is intended to be reachable only from inside the cluster or over a VPN.
- Weak or default admin credentials that were never changed from `admin/admin`.
- Issues in upstream services that thorngate proxies to.
- Vulnerabilities in Cloudflare, Kubernetes, or the Go standard library
  itself; report those to the respective projects.

## Dependencies

The Go binary uses only the standard library. The admin portal's npm
dependencies are build-time only and are embedded as static assets. Dependabot
monitors both, plus the GitHub Actions and Docker base images used in CI.
