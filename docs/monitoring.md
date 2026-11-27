# Local monitoring and reporting

Original Agent code using the inherited Dashboard model and the separately licensed gopsutil v4.26.10 dependency. No official Nezha Agent source is imported. The collector does not call public IP, geolocation, or update services.

Initial metrics: CPU, memory, swap, system/root filesystem capacity and usage, boot time, uptime, OS, architecture, cumulative network counters and calculated transfer rates. Network counters are OS aggregate counters, not billing-grade WAN-only traffic; virtual and loopback interface traffic may be included. Network resets and first measurements produce zero rate. GPU, load, temperature, per-interface filtering, process and connection counts are not implemented yet; legacy numeric fields default to zero and cannot distinguish unsupported from real zero.

The reporting loop sends host before state, refreshes host every five minutes and retries failed reports with capped exponential backoff. Caller supplies context and transport; the loop has no task execution or upgrade capability. No executable or service integration is added in this commit. Real local sampling tests run on Linux and Windows; the retry/order tests use a mock reporter, not an actual Dashboard. Dependency checksums will be locked after CI resolves the new dependency.
