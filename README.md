# NeZha Agent v0.30.00 — independent monitoring client

Development baseline: `onecat/nezha` Dashboard v0.30.05 at `00e52449eb0d2d2639e9fc5a2d3a9da2e837ff1c`. The Agent implementation is independent; no official Agent source snapshot is used by current builds. A prior import exists only in Git history.

## Implemented and verified

- A runnable original Agent with local JSON configuration, certificate-validated TLS/gRPC, Host and State reporting, configurable IPv4/IPv6 discovery (Cloudflare default; custom HTTPS endpoints or disabled), and local Dashboard GeoIP lookup.
- Linux amd64/arm64 Agent and Supervisor builds, signed offline upgrade verification, durable local upgrade ledger, atomic installation and failure rollback. Upgrade remains disabled until explicit operator provisioning.
- Dashboard v0.30.06 joint CI exercises real TLS-connected Dashboard, Agent and Supervisor processes on native Linux amd64 and arm64 runners. It tests first reports, signed canary, two-target wave, bad-version rollback, restart persistence and paused-task reconciliation.
- Windows amd64 baseline monitoring build, unit tests and TLS/IP behavior are retained. Windows managed installation, downgrade persistence, Supervisor service management and automatic rollback are **out of scope** and not qualified.

## Limits and migration

This Agent is **not a drop-in replacement** for the legacy v0.20.5 Agent. Remote terminal, tunnels, command execution, some monitoring metrics and other legacy Agent features remain unimplemented or unqualified. Keep legacy Agents on hosts that need those functions. Migration from v0.20.5 is manual; do not run old and new Agents with the same secret concurrently. See `docs/linux-deployment.md`.

Local metrics currently include CPU, memory, swap, root filesystem, uptime, boot time, OS, architecture and aggregate network counters/rates. GPU, load, temperature, process and connection counts are not yet reported. Local Dashboard DDNS and notifications remain Dashboard-owned behavior; end-to-end feature compatibility has not been established.

The release artifacts are not operator-signed .nzu packages. Generate signing keys offline, keep private keys out of CI and services, and follow `docs/managed-upgrade-runner.md` and the Dashboard's `docs/managed-upgrade-operations.md`. No official NeZha runtime service or upstream automatic updater is required.

## Verification

Agent CI: https://github.com/onecat/nezha-agent/actions/runs/45934302210

Dashboard paired native CI: https://github.com/onecat/nezha/actions/runs/45934319157

These tests establish the listed paths, not full legacy monitoring parity or production acceptance. Publishing a GitHub release does not install or activate the service in production.
