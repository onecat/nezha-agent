# Source baseline correction

Source: https://github.com/onecat/nezha/tree/00e52449eb0d2d2639e9fc5a2d3a9da2e837ff1c
Tag: v0.30.05. The user specified this local Dashboard as the only development baseline, not nezhahq/agent.

Imported unchanged: LICENSE, proto/nezha.proto, proto/nezha.pb.go, proto/nezha_grpc.pb.go and go.sum. Adapted model/host.go to use the independent module. go.mod is a minimal derivative of the Dashboard's gRPC/protobuf dependency versions; checksums are retained until dependency pruning is reviewed.

The previous upstream import is removed from the current tree, including its write-enabled import workflow. History is preserved without force pushing. No external upstream source import is configured.

The existing Dashboard has unary ReportSystemState, ReportSystemInfo and ReportTask, server-streaming RequestTask(Host), bidirectional IOStream and unary LookupGeoIP. Keep exact schema semantics. The Dashboard has no Agent executable; implement authenticated connection, monitoring, supported task handling and managed upgrade supervisor, then test against the local Dashboard. No release before full validation.
