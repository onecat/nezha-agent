# NeZha Agent — internal managed upgrade

Independent Agent repository for the onecat NeZha deployment. Development target: v0.30.00; v0.30.01 is reserved for real managed upgrade and rollback verification. No production release or installation instructions are available yet.

## Compatibility and safety

- Dashboard development target: v0.30.06.
- Legacy v0.20.5 installations require manual migration.
- Managed upgrades default to disabled; only explicit authenticated Dashboard tasks may request a signed package.
- Certificate-verified TLS, offline Ed25519 signing, monotonic release sequence and local rollback are required.
- No upstream automatic update, release synchronization, contributor synchronization or external IP discovery by default.
- Initial targets: Linux amd64/arm64 and Windows amd64.

## Source provenance

The intended compatibility baseline is upstream nezhahq/agent tag v0.20.5, commit `c0d3615941f5afcb4833770509b049439b3e2559` (2024-11-24). That historical tree does not include a LICENSE file. A later upstream commit `50e574ccda72fd39ee3ad11f078824478fdd46b2` introduced Apache-2.0 terms in March 2025; commit `878a86a31b009d4479b7b4803e62e53b3da5597e` changed the license in October 2026. These later notices are not treated as conclusive authorization for redistribution of every historical blob. The old source import is pending provenance review. This initial repository contains only original project documentation.

Development work is kept separate from production releases. Never commit signing private keys, Agent secrets or deployment credentials.
