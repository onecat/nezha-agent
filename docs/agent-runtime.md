# Development monitor executable

Build with go build ./cmd/agent. This is a monitoring-only development executable, not a release candidate. It does not yet subscribe to tasks, execute commands, install a service or support upgrades.

Use a private JSON file (Unix mode 0600; on Windows restrict ACL to the service account and administrators). Example keys: server (TLS reverse proxy host:port), client_secret, ca_file (optional internal CA PEM), report_interval_seconds (default 5), enable_ip_query (default true), ip_query_ipv4 and ip_query_ipv6 (default true), ip_query_endpoints (optional list of HTTPS trace/plain-IP services), prefer_ipv6_geo (default false). Set enable_ip_query false for a fully internal deployment. Configuration is local only; unknown fields and duplicate keys fail closed. Never pass a secret on the command line or commit it. Config and CA files must be in a trusted operator-controlled directory.

The process runs in the foreground with signal cancellation. Native Windows service and Linux service installation remain future work. Managed upgrade is not enabled. Use only in a non-production test environment. Cross-platform CI compiles the executable and tests configuration.
