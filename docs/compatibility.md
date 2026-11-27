# Compatibility gate

Pinned upstream: 93936422dc010aaaf82428c775139b4953b4c9aa. Local Dashboard protocol: 243f8aa7aa0705b51d9bd711d2183778b7325491.

The upstream source must not be connected to the production v0 Dashboard without adaptation.

| Area | Upstream | Local Dashboard |
| --- | --- | --- |
| ReportSystemState | bidirectional stream | unary |
| RequestTask | bidirectional TaskResult/Task | Host request, streamed Task |
| ReportTask | absent | unary |
| GeoIP | ReportGeoIP | LookupGeoIP |
| Host field 10 | version | ip |
| Host field 11 | repeated gpu | deprecated country_code |
| Host fields 12/13 | absent | version/gpu |
| State | memory at field 2, shifted subsequent fields, repeated GPU at 17, detailed GPUs at 18 | memory at field 3, scalar GPU at 18 |

Do not reinterpret existing field numbers or accept the newer wire protocol on the legacy endpoint. Generate a separate v0 compatibility protocol/client, map semantic fields explicitly, check authentication metadata and task numbers, then verify monitor reports and task lifecycle with real gRPC integration tests. Keep new upstream-only task handlers unreachable unless explicitly approved and tested. Reserve the managed-upgrade extension only after confirming both ends agree.

The upstream source contains self-update and other network features; importing it is not the same as disabling them. No release or deployment until removal and regression tests are complete.
