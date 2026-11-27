# Shared managed upgrade core

The following files are copied unchanged from the local Dashboard development commit 2e291201a86ef8eac6d787c3b6dcc9fe42132892, under the existing Apache-2.0 license. This is the project's own implementation, not upstream Agent source.

- authorization.go: 220f8a78691429b2f88c60527048ae0212ce71b6
- authorization_test.go: 379121db2cae01f98a8ca6bffc37b884394e6a08
- build.go: 29f69fd6bb3ef23b116a092ac7f7679b439d45af
- build_test.go: 7dc8d6fb35e7ee7f32e4e832dc99b0d893ae714e
- package.go: 68145f37675eea3b54a9eff3faf14050501306b6
- package_test.go: 2eff381972763c69c18cfc4642787dd387ccc7b7
- recovery.go: 2d27aa650820d94a9aa97c621977748de1172b98
- recovery_test.go: af224356ff73f8386d942fd45bdf390137a48b2c
- sender.go: 22637c5814e7b142e82cca86fb58b456a97bd742
- sender_test.go: 0db82ae774b9c9554984dc80dd87b31fc5e3287a
- snapshot.go: 0d2d45e35e8c4bbbb63187813080423a140bd344
- snapshot_test.go: da3196d114555a52b498c51ed00286e756ad8963
- transaction.go: 4b33b72726238b43e1a7daf1162bb3a117e8f2d6
- transaction_test.go: 2c560b34aa5fbea810dce6188d979451d8c99696
- transfer.go: 6de2f875e6ee0fc0fc8ba0a0f21e50a652e93b94
- transfer_test.go: 04a9511b11d4f6119342af28c3f0c423a854f28a

The Agent and Dashboard now use matching NZU verification, signed manifest format, task binding, chunk protocol, snapshot encoding and state transition rules. The extra round-trip test exercises a signed multi-chunk package from sender to receiver, verification, version and sequence checks, and serialization. Test keys and data are ephemeral fixtures only.

This is not an installer or a network transport. No trusted keys have been provisioned, no task handler enabled, no persistent sequence store or supervisor implemented. The receiver must eventually use an immutable private staging file, not a live executable. The shared copies must be kept in sync by future changes; there is no automatic upstream sync. The offline builder is included to exercise cross-side format compatibility in tests, and is not called by the Agent executable.
