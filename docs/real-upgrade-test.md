# Linux local signed upgrade integration

CI now builds two real Agent executables from the same development source tree using linker-set v0.30.00 and v0.30.01 version labels. It creates a signed package with a disposable Ed25519 key, transfers it in bounded chunks to a private staging file, verifies it, persists the sequence and task, stops the actual old Agent, installs the new executable and checks authenticated reports through a private readiness pipe.

Two cases exercise success and a fixture that accepts new host reports but rejects new state reports. The latter triggers a bounded upgrade timeout, restores the previous executable, starts the old Agent and checks its readiness. Both verify executable bytes, persistent terminal state and sequence after reopening, and replay rejection.

This is a Linux integration test using real Agent processes and a local TLS gRPC fixture, not the complete Dashboard executable or remote transport. The binaries share the same development source; they are not independently released versions. The test does not enable production upgrades, install system services, publish releases, use production keys or contact public IP services. Native Windows and arm64 execution, actual Dashboard integration and production supervisor wiring remain required.
