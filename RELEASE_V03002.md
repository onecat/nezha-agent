# Agent v0.30.02

Linux amd64 network accounting fix. Physical NICs and bond masters are counted once; virtual forwarding legs and bond members are excluded by default. Guest/container fallback and optional local network_interfaces allowlist are supported. Independent RX/TX deltas handle interface changes and counter resets. The cumulative baseline may change on upgrade/restart or interface selection changes; historical Dashboard traffic is not rewritten.

Compatible with Dashboard v0.30.08 URL upgrade and the existing enrolled v0.30.01 Supervisor. No protocol, signing, task or rollback changes. New installations use the included Supervisor and one-time enrollment. Existing installations update the raw worker binary without resetting state. No upstream updates. Linux amd64 only.

CI includes synthetic PVE topology, Linux sysfs fixtures, asymmetric traffic, counter reset and interface replacement tests, real Agent process and signed upgrade/rollback, race, vet and vulnerability checks. Production PVE traffic has not been measured by CI.
