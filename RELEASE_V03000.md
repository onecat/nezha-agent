# Nezha Agent v0.30.00

First independent Agent release for the local Nezha Dashboard project. Linux amd64 and arm64 monitoring and explicitly provisioned managed upgrades. Includes the independent supervisor, systemd template, private configuration/migration instructions, licenses, source identity and SHA256 checksums.

- Certificate-validated TLS, configurable public IP discovery (Cloudflare by default; disable for closed networks).
- No automatic upstream version checks or upstream Agent installer.
- Explicit local trusted signing keys, durable sequence and task state, rollback after failed health checks.
- Managed upgrades require manual local provisioning and matching Dashboard v0.30.06 authorization. Ordinary Agent mode does not enable managed upgrades.
- The native amd64/arm64 test suite, Windows baseline tests and dependency/security gates must pass before the release job runs. Windows installation/managed rollback and Windows release packages are deferred.
- This is a monitoring/managed-upgrade Agent, not a full feature replacement for legacy v0.20.5 remote terminal, tunnel, task execution and all monitoring metrics. Keep legacy installations where needed.
- The installation archives are checksum-protected distribution files, not production-signed .nzu upgrade packages. Sign release packages offline with your own key. No production key, test private key or fault-injection binary is included.
- v0.30.01 in Dashboard CI is a same-source upgrade-validation fixture, not a separate production release.

Follow the included linux-deployment.md and verify SHA256SUMS from a trusted release source before installation. No production service is changed by publishing this release.
