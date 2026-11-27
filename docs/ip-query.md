# Public IP compatibility

Public IP discovery is an optional component, separate from local metric collection. DefaultConfig enables IPv4 and IPv6 using the three Cloudflare trace endpoints historically used by legacy Agents. Operators can replace the endpoint list with their own HTTPS service (plain IP or trace ip= format), or disable all discovery. No Nezha official service is used. The component does not send Dashboard secrets, follow redirects, use environment HTTP proxies, or disable certificate verification.

Queries are bounded by a common eight-second timeout and an 8 KiB response limit. Both IP families are queried separately. The response must be a public unicast address of the correct family; the checks reject common private, loopback and documentation ranges, not an exhaustive registry of all special-use allocations. Addresses use the existing IPv4/IPv6 slash-separated Host.ip representation.

This commit adds the independently testable discovery module only. It does not yet schedule periodic queries, populate Host.ip, invoke LookupGeoIP, or modify DDNS behavior. The planned Agent configuration will use a 300-second default interval and allow fully offline deployments. Tests use local TLS fixtures; no live Cloudflare service is contacted by CI.
