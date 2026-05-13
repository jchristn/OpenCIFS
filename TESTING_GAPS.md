# Testing Gaps

Reviewed on 2026-05-13.

Bottom line: the repository has strong internal coverage and bounded external interoperability coverage, but it is not yet at full interoperability testing.

## 1. OpenCIFS client against a live Docker CIFS server

Current state: partially covered.

What exists:
- `eng/run-samba-interop.ps1` runs `OpenCIFS.Client` against a Dockerized Samba server.
- `docs/interop-matrix.md` records passing evidence for `OpenCIFS.Client -> Samba server` on SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- The current Docker peer is Samba `smbd` 4.17.12 on Debian bookworm.

Gaps:
- Only one live Docker server implementation is covered: Samba.
- No Windows server coverage exists for `OpenCIFS.Client`; `docs/interop-matrix.md` marks `OpenCIFS.Client | Windows server | Unassigned`.
- No additional server products or versions are covered.
- Coverage is bounded smoke/deeper-smoke, not a broad command-by-command interoperability matrix.
- External durable-handle v2 coverage is still backlog.
- Broader SMB 3.x external coverage is still backlog.
- The checked-in evidence currently stops at SMB 3.0.2 even though the scripts now define an `Smb311` lane.
- The release validator still only requires `smb2002`, `smb21`, and `smb302` for external interop artifacts.

## 2. OpenCIFS client against an OpenCIFS server

Current state: strongly covered for internal managed-path regression, but not enough to claim full interoperability.

What exists:
- `src/OpenCIFS.Client.Tests.Shared/ClientTestSupport.cs` starts a real `OpenCifsDirectTcpServer` on loopback and exercises the client over direct TCP.
- `docs/coverage-matrix.md` records extensive live-listener managed client coverage over `OpenCifsDirectTcpServer`.
- `src/OpenCIFS.Interop.Tests.Shared/InteropTestSuites.cs` provides broad loopback suites for negotiate, session/tree, file I/O, metadata, locking, notify, oplocks, leases, durable handles, compound requests, and IOCTLs.
- `eng/run-test-console-smoke.ps1` runs `OpenCIFS.TestClient` and `OpenCIFS.TestServer` as separate processes and drives end-to-end operations over loopback.

Gaps:
- Much of the dedicated `Interop` suite is in-process loopback coverage, not a socket-level two-process interop harness.
- There is no release-gated dialect-by-dialect managed client/server interop artifact comparable to the Samba and Windows external artifacts.
- There is no managed client/server cross-version matrix, such as released client N against released server N-1 or N+1.
- There is no Dockerized OpenCIFS server harness used as a standard interop target.
- There is no long-running two-process managed client/server interoperability soak comparable to the external nightly composition.
- Because both ends come from the same codebase and same commit, this is strong regression coverage but weaker evidence of independent interoperability behavior.

## 3. OpenCIFS server against a live Docker CIFS client

Current state: partially covered.

What exists:
- `eng/run-samba-interop.ps1` runs Dockerized Samba `smbclient` against `Sample.OpenCifsServer`.
- `docs/interop-matrix.md` records passing evidence for `Sample.OpenCifsServer -> Samba client` on SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- The current Docker peer is Samba `smbclient` 4.17.12 on Debian bookworm.

Gaps:
- Only one live Docker client implementation is covered: Samba `smbclient`.
- There is no Linux kernel CIFS client coverage such as `mount.cifs` or `cifs-utils`.
- There is no additional live Docker client diversity beyond Samba userland.
- Coverage is bounded smoke/deeper-smoke, not a broad command-by-command interoperability matrix.
- External durable-handle v2 coverage is still backlog.
- Broader SMB 3.x external coverage is still backlog.
- The checked-in evidence currently stops at SMB 3.0.2 even though the scripts now define an `Smb311` lane.

## 4. OpenCIFS server against an OpenCIFS client

Current state: strongly covered for internal managed-path regression, but not enough to claim full interoperability.

What exists:
- `src/OpenCIFS.Client.Tests.Shared/ClientTestSupport.cs` starts `OpenCifsDirectTcpServer` and drives the managed client against it over real loopback TCP.
- `docs/coverage-matrix.md` records extensive direct-TCP managed client coverage against the managed server.
- `eng/run-test-console-smoke.ps1` runs `OpenCIFS.TestClient` against `OpenCIFS.TestServer` as separate executables.
- `src/OpenCIFS.Interop.Tests.Shared/InteropTestSuites.cs` covers a broad set of managed loopback protocol behaviors.

Gaps:
- There is no standard two-process, artifact-producing, dialect-matrix managed interop harness that is treated like the external Samba and Windows runs.
- There is no released-binary or cross-version managed client/server compatibility matrix.
- The strongest managed-path suites are still same-repo and mostly same-build coverage.
- There is no Dockerized managed client or server lane for reproducible OpenCIFS-to-OpenCIFS interoperability runs.

## Cross-cutting gaps

### External interop is not in always-on CI

- `.github/workflows/ci.yaml` runs build, Touchstone, and framework tests only.
- The GitHub Actions workflow does not run `eng/run-integration-gates.ps1`.
- The external interop harnesses are composed locally by `eng/run-integration-gates.ps1` and `eng/run-release-gates.ps1`, but they are not part of the default CI signal.

Impact:
- External interop regressions can land without being caught by GitHub Actions.

### Evidence is stale relative to the current date

- The interop matrix rows are last verified on 2026-04-30.
- The current review date is 2026-05-13.

Impact:
- The repository does not currently carry same-day or near-current external interop evidence.

### SMB 3.1.1 preview coverage is not consistently reflected in evidence and gates

- `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, and `eng/run-windows-client-interop.ps1` all define an `Smb311` dialect lane.
- The checked-in `docs/interop-matrix.md` still claims only SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- The checked-in external interop artifacts currently contain `smb2002`, `smb21`, and `smb302` only.
- `eng/validate-release-artifacts.ps1` still requires only `smb2002`, `smb21`, and `smb302`.

Impact:
- Harness capability, checked-in evidence, and release gating are not aligned for SMB 3.1.1 preview interop.

### Windows server interoperability is still missing

- `docs/interop-matrix.md` explicitly marks `OpenCIFS.Client | Windows server | Unassigned`.
- `docs/coverage-matrix.md` also calls out `OpenCIFS.Client` to Windows server coverage as backlog.

Impact:
- There is no evidence that the managed client interoperates with a live Windows SMB server.

### Peer diversity is limited

- External server-side coverage is effectively Samba plus the built-in Windows client against the sample server.
- External client-side Docker coverage is only Samba `smbclient`.
- There is no Linux kernel CIFS client coverage.
- There is no multi-version Samba matrix in the checked-in evidence.

Impact:
- The current interop story is bounded vendor coverage, not broad ecosystem coverage.

### DFS external interoperability is missing

- `docs/coverage-matrix.md` states that external Windows or Samba DFS interop remains backlog.

Impact:
- Managed DFS behavior is covered internally, but not proven against real external DFS peers.

### Durable and advanced SMB 3.x external interoperability is incomplete

- The interop matrix and coverage matrix repeatedly call out durable-handle v2 external interop as backlog.
- Broader SMB 3.x nightly or external coverage remains backlog.
- SMB 3.1.1 external interop remains backlog and is still preview-only.

Impact:
- Advanced reconnect, lease, and modern SMB 3.x behavior is not externally proven end to end.

### SMB1/CIFS real interoperability is still backlog

- The repository has SMB1 codec and bootstrap coverage, but real SMB1 client/server interop remains backlog.

Impact:
- If "full CIFS interoperability" includes real SMB1 peers, the project is not there yet.

### Kerberos interoperability is still backlog

- The coverage matrix marks native Kerberos for SMB as backlog.

Impact:
- Full enterprise interoperability is not yet covered.

## Conclusion

The repository is not yet at full interoperability testing.

What it has today:
- Strong unit, shared, loopback, and managed direct-TCP regression coverage.
- Bounded external interoperability against Samba in Docker.
- Bounded external server coverage against Windows built-in SMB client.

What is still missing for a full interop claim:
- `OpenCIFS.Client -> Windows server`.
- Broader peer diversity beyond Samba.
- Linux kernel CIFS client coverage.
- Always-on CI execution of the external interop stack.
- Consistent SMB 3.1.1 evidence and gating.
- External DFS, durable-handle v2, broader SMB 3.x, Kerberos, and real SMB1 interoperability coverage.
- Cross-version managed client/server compatibility testing.
