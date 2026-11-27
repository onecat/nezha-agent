# Linux managed Agent service (qualification only)

Use the included systemd unit as an explicit local installation template. Create a dedicated nezha user/group, protect the supervisor executable and all directory ancestors, and provision a private agent configuration and supervisor configuration under /etc/nezha readable only by that account. Under /var/lib/nezha-agent create separate install, state and staging directories owned by that user, mode 0700. Install the independently verified Agent v0.30.00 binary as install/nezha-agent with mode 0700. Install the supervisor separately in /usr/local/bin owned by root. Configure absolute paths, trusted public keys, matching server ID and initial sequence. Stop and disable any old Agent service first; do not run two workers using the same secret. Initialize the supervisor ledger exactly once as the service account; never reset an existing ledger. Copy the unit into /etc/systemd/system and enable it only after acceptance. The unit confines writes to /var/lib/nezha-agent and uses the service cgroup to contain children. Non-root monitoring may have restricted sensor/process visibility. No official Agent installer or upstream update URL is used.

The development ledger schema 1 is not automatically migrated. If an experimental ledger exists, reconcile its sequence and pending task with the operator instead of deleting it. The stable v0.20.5 manual migration does not use this experimental ledger. Native arm64 CI is added to execute the real Linux integration tests, not just cross-compile. No production installation performed.

## Manual migration from v0.20.5

The replacement is a new monitoring/managed-upgrade Agent, not a full legacy feature clone. Inventory the old installation first. If it relies on remote terminal, tunnel, command execution, service monitor tasks, or metrics not yet collected by this Agent, keep that host on its existing Agent until the corresponding features are qualified. Do not run two agents with one secret. No old automatic updater is copied or invoked.

1. Back up the original binary, local configuration, service unit and startup arguments in a private operator-only directory. Record the existing Dashboard server ID and secret locally; do not print them or regenerate the server unnecessarily.
2. Select the candidate for the actual CPU architecture. Verify SHA256SUMS from a trusted CI/release source. Install the supervisor independently under /usr/local/bin; place the v0.30.00 binary as /var/lib/nezha-agent/install/nezha-agent. Use the dedicated account and directories described above.
3. Translate the existing server address and client secret into private agent.json (sample below). Use a TLS hostname and port covered by the configured certificate. For an internal CA, supply an absolute CA PEM path. Preserve the existing IP discovery preference; set enable_ip_query=false only for intentionally closed deployments.
4. Provision the matching server ID, approved initial sequence and offline signing public key in supervisor.json; the Dashboard's allowlist must use the same identity, architecture, initial sequence and secret fingerprint. Do not copy an offline private key onto either service. Initialize the ledger once while no supervisor or old Agent is running. Use the included systemd service template.
5. Check authenticated Host/State reports in Dashboard before permitting any managed upgrades. Test a single canary first. The signed v0.30.01 package must be created offline by the operator. Do not reuse a consumed release sequence after failed installation or rollback.
6. For a failed initial migration before any managed task has been reserved, stop the supervisor and restore the backed-up legacy service with the original server identity. For a host with a managed ledger, preserve that ledger and all backups and reconcile the version and high-water mark before any manual binary changes. Never delete the state directory to retry a release.

### agent.json example (placeholders, not usable credentials)

```json
{
  "server": "agent.example.invalid:443",
  "client_secret": "REPLACE_WITH_EXISTING_SECRET",
  "ca_file": "/etc/nezha/ca.pem",
  "report_interval_seconds": 5,
  "enable_ip_query": true
}
```

### supervisor.json example (placeholders)

```json
{
  "enabled": true,
  "server_id": 123,
  "initial_sequence": 1,
  "initial_version": "v0.30.00",
  "agent_config": "/etc/nezha/agent.json",
  "install_dir": "/var/lib/nezha-agent/install",
  "state_dir": "/var/lib/nezha-agent/state",
  "stage_dir": "/var/lib/nezha-agent/stage",
  "keys": {"operator-key": "REPLACE_WITH_64_HEX_PUBLIC_KEY"}
}
```

These are manual deployment instructions, not an executed production migration. Unresolved local persistence failures stop the worker and require recovery; keep the service cgroup, private state and backups intact.
