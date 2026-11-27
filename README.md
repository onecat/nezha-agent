# NeZha Agent — internal managed upgrade

Independent Agent project for onecat NeZha. Target v0.30.00; v0.30.01 is reserved for actual upgrade and rollback verification. No production release yet.

## Source baseline

The approved baseline is the upstream nezhahq/agent main commit 93936422dc010aaaf82428c775139b4953b4c9aa (2026-11-21), after the latest stable v2.4.0 release. The upstream tree includes WTFPL; preserve its LICENSE and attribution. Import only the pinned snapshot, not upstream synchronization, release, contributor, or deployment workflows. The one-time import workflow is build-time only, not an Agent runtime dependency.

Legacy v0.20.5 installations require manual migration, but their source is no longer the development baseline. The new upstream wire protocol is NOT compatible with the existing v0 Dashboard; compatibility must be explicitly implemented and tested before use. Do not run the unmodified upstream Agent in production.

## Requirements

- Dashboard target v0.30.06.
- Certificate-verified TLS, offline Ed25519 signing, monotonic release sequence and local rollback.
- Managed upgrades default to disabled, triggered only by authorized Dashboard tasks.
- Remove upstream auto-update and external IP discovery by default.
- Initial targets Linux amd64/arm64 and Windows amd64.
- Never commit signing keys, deployment credentials or Agent secrets.

See docs/compatibility.md for initial protocol differences. The main branch remains an initialization branch; all development is on managed-upgrade-v0.30.00.
