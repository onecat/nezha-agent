# Agent v0.30.03

Linux amd64 single binary. Native service install/reinstall/uninstall (uninstall retains configuration and ledger), status and restart. No Python, shell installer or separate Supervisor release. systemd directly runs Agent with Type=notify; the old executable inode is retained as a private short-lived ExecStartPre recovery command, not a daemon. Signed package and monotonic sequence retained; first candidate launch has one attempt, next start restores previous bytes if health fails. Legacy --supervised mode and historical source tests retained for compatibility, not the default service.

Install from verified release binary as root: printf '%s\n' 'SECRET' | ./nezha-agent service install --server 'agent.example:443'. Private CA via --ca-file. Existing direct installations can reinstall exactly the ledger version; existing managed layouts are refused rather than resetting a ledger and must migrate explicitly. Legacy v0 directory is backed up. New service uses /opt/nezha/agent/nezha-agent and nezha-agent.service. Agent configuration is agent.json; hidden state/stage and backup files remain necessary. No upstream update endpoints. PVE network fixes retained.

CI verifies direct recovery state and existing protocol regressions. Dashboard v0.30.10 separately qualifies real systemd install/reinstall and live upgrade. No production deployment performed.
