# Local Dashboard transport

The client uses the exact local v0.30.05 protobuf and client_secret metadata. It requires a certificate-verified TLS endpoint, system roots or an explicitly provided internal CA, and never falls back to plaintext or skips hostname verification. Dashboard's existing gRPC listener is plaintext; TLS termination at the operator's existing reverse proxy is required. The reverse proxy to Dashboard network must also be trusted and protected. Unary reports have ten-second deadlines and require positive receipts. Task streaming is transport only; caller owns cancellation. No commands, task execution, upgrade, external IP lookup or automatic update are enabled by this package.

CI tests use a real loopback TLS gRPC server implementing the inherited contract, including invalid certificate trust, wrong secret and plaintext rejection. This is not yet a test against the actual Dashboard process.
