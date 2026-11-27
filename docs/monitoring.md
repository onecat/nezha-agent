# Local monitoring and reporting

Original Agent code using the inherited Dashboard model and the separately licensed gopsutil v4.26.10 dependency. No official Nezha Agent source is imported. The collector does not call public IP, geolocation, or update services.

Initial metrics: CPU, memory, swap, system/root filesystem capacity and usage, boot time, uptime, OS, architecture, cumulative network counters and calculated transfer rates. Network counters are OS aggregate counters, not billing-grade WAN-only traffic; virtual and loopback interface traffic may be included. Network resets and first measurements produce zero rate. GPU, load, temperature, per-interface filtering, process and connection counts are not implemented yet; legacy numeric fields default to zero and cannot distinguish unsupported from real zero.

The reporting loop sends host before state, refreshes host every five minutes and retries failed reports with capped exponential backoff. Caller supplies context and transport; the loop has no task execution or upgrade capability. No executable or service integration is added in this commit. Real local sampling tests run on Linux and Windows; the retry/order tests use a mock reporter, not an actual Dashboard. Dependency checksums will be locked after CI resolves the new dependency.


## Network accounting (v0.30.02)

Linux automatic selection prefers physical NICs and bond masters, excluding bond slaves, Linux bridges, TAP/TUN, loopback and common container/firewall forwarding interfaces. Physical interfaces enslaved to a bridge remain eligible. If no physical NIC or bond is visible, ordinary non-bridge interfaces such as a guest/container eth0 can be selected. For routed tunnels, VLAN-only accounting, unusual names, bridge-only networks or separating management/storage traffic, set an exact non-overlapping local allowlist in agent.json:

    "network_interfaces": ["eno1", "eno2"]

An omitted or empty list uses automatic mode. An explicit missing interface is not replaced by an unrelated interface. Rates are independent per-interface RX/TX counter deltas; new/recreated interfaces are baselined, and counter resets do not create artificial speed spikes. Cumulative totals start from selected interface lifetime counters at process start, then accumulate observed deltas; removed interfaces remain in the running process total. Restart, changing the selected interfaces, or upgrading from all-interface accounting can change the cumulative baseline. Historical Dashboard traffic is not rewritten. Choose one accounting layer; explicitly selecting both a bridge and its forwarding ports can still double-count.
