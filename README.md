# NeZha Agent — internal managed upgrade

Development baseline: onecat/nezha Dashboard v0.30.05, commit 00e52449eb0d2d2639e9fc5a2d3a9da2e837ff1c.
This supersedes the earlier upstream Agent import. No official Agent snapshot is used in the current source tree. The previous import remains in Git history; do not use it for builds.

The Dashboard repository does not contain a full Agent executable. This repository starts with its exact protobuf schema and generated Go bindings, host data model (local module import adapted), Apache-2.0 license and pinned dependency checksums. A native Agent client must be implemented and validated separately. No runnable Agent or release exists yet.

Targets: Agent v0.30.00, Dashboard v0.30.06, actual upgrade/rollback validation with Agent v0.30.01. Legacy v0.20.5 installations require manual migration. Preserve existing wire field numbers and RPCs. No upstream automatic update or external IP discovery by default. Managed upgrade disabled by default, certificate-verified TLS, signed offline packages, persistent anti-rollback sequence and local recovery required. No production credentials or private signing keys in source or CI.
