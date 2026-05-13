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

## Actionable developer work queue

Keep this section as the execution register for the gaps above. When an item lands, update its status, the linked matrix rows, the release validator if the evidence became required, and the evidence date. If a run is intentionally skipped, record the reason in the relevant matrix row instead of deleting the item.

| ID | priority | status | action | done when | primary files or commands to update |
| --- | --- | --- | --- | --- | --- |
| TG-001 | P0 | open | Add `OpenCIFS.Client -> Windows server` interop coverage. Build a harness that provisions or targets a live Windows SMB share, runs the managed client against it for SMB 2.0.2, SMB 2.1, and SMB 3.0.2, and writes a JSON artifact with environment details, dialect IDs, pass/fail state, and exercised operations. | `docs/interop-matrix.md` no longer has `OpenCIFS.Client | Windows server | Unassigned`; `docs/coverage-matrix.md` records Windows-server verification dates for the managed client path; the harness can be run from `eng/run-integration-gates.ps1` or `eng/run-release-gates.ps1`. | Add a script under `eng/`, update `docs/interop-matrix.md`, update `docs/coverage-matrix.md`, consider adding the artifact to `eng/validate-release-artifacts.ps1`. |
| TG-002 | P0 | open | Decide the SMB 3.1.1 preview interop policy and align scripts, docs, and gates. Either require `smb311` artifacts everywhere the current scripts define an `Smb311` lane, or explicitly mark the lane as preview-only and non-release-gated. | `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `docs/interop-matrix.md`, and `eng/validate-release-artifacts.ps1` agree on whether `smb311` is required; release validation fails if a required SMB 3.1.1 artifact is missing. | Update the three interop scripts, `docs/interop-matrix.md`, `docs/coverage-matrix.md`, and `$requiredInteropDialectIds` in `eng/validate-release-artifacts.ps1`. |
| TG-003 | P0 | open | Put external interop into recurring CI. Add a scheduled and manually triggered workflow that runs the external interop stack on runners with the required Docker and Windows SMB prerequisites, uploads artifacts, and fails on harness failures. | GitHub Actions produces current interop artifacts for Samba, Python `smbprotocol`, and Windows-client lanes; failures block the scheduled signal; the matrix dates can be refreshed from CI artifacts rather than local-only runs. | Add or extend `.github/workflows/*.yaml`; call `eng/run-integration-gates.ps1` or the individual interop scripts; upload `artifacts/*interop*` and `artifacts/nightly-interop`. |
| TG-004 | P1 | open | Add Linux kernel CIFS client coverage against `Sample.OpenCifsServer`. Use a Docker or privileged Linux runner lane with `cifs-utils`/`mount.cifs`, mount the sample share, and exercise create, read, write, metadata, rename, delete, lock conflict, and dialect pinning where supported. | `docs/interop-matrix.md` has a `Sample.OpenCifsServer | Linux kernel CIFS client` row with pass evidence and a current date; the artifact records kernel, cifs-utils, mount options, dialect, and operation results. | Add Docker or workflow support under `eng/docker/` and `eng/`; update `docs/interop-matrix.md` and `docs/coverage-matrix.md`; consider `eng/validate-release-artifacts.ps1` once stable. |
| TG-005 | P1 | open | Add a standard two-process OpenCIFS-to-OpenCIFS interop harness. Run published or built `OpenCIFS.TestServer` and `OpenCIFS.TestClient` as separate processes across the same dialect matrix used for external peer testing, and emit an artifact comparable to Samba and Windows artifacts. | `OpenCIFS.Client -> OpenCIFS server` and `OpenCIFS server -> OpenCIFS client` have artifact-backed rows in `docs/interop-matrix.md`; the harness is callable from integration or release gates; the artifact records process versions, dialect IDs, and operations. | Extend `eng/run-test-console-smoke.ps1` or add a new `eng/run-managed-interop.ps1`; update `docs/interop-matrix.md`; optionally add release artifact validation. |
| TG-006 | P1 | open | Add managed client/server cross-version compatibility coverage. Test current client against the previous released server and current server against the previous released client, using published packages or release artifacts instead of same-commit projects. | A cross-version compatibility artifact exists with package or commit versions; `docs/interop-matrix.md` records N-to-N-1 coverage; release notes can cite explicit compatibility evidence. | Add an `eng/` harness that restores or downloads released packages; update `docs/interop-matrix.md`; add artifact checks if this becomes release-gated. |
| TG-007 | P1 | open | Expand peer diversity beyond the current Samba 4.17.12 image. Add at least one additional Samba version or distribution image and record exact versions in evidence. | `docs/interop-matrix.md` distinguishes each Samba target version or records a multi-version matrix; artifacts include `smbd`, `smbclient`, OS, and Docker image identifiers. | Add Dockerfiles or build arguments under `eng/docker/samba-interop/`; update `eng/run-samba-interop.ps1`, `docs/interop-matrix.md`, and `docs/coverage-matrix.md`. |
| TG-008 | P1 | open | Add external DFS interoperability. Exercise managed DFS referral handling against a real Windows or Samba DFS namespace, including referral retrieval, cache behavior, and at least one redirected tree connect path. | `docs/coverage-matrix.md` no longer marks external DFS interop as backlog; `docs/interop-matrix.md` has a DFS row with artifact-backed pass evidence. | Add an interop script under `eng/`; update `docs/coverage-matrix.md`, `docs/interop-matrix.md`, and release validation if required. |
| TG-009 | P1 | open | Add external durable-handle v2 and broader SMB 3.x behavior coverage. Extend the external interop artifacts to include durable create, disconnect, reconnect, preserved byte-range lock behavior, and lease/oplock behavior where the peer supports it. | Samba, Windows-client, and Python-client artifacts explicitly report durable-handle v2 or a peer-capability skip reason; matrix notes stop calling durable-handle v2 a blanket backlog item. | Update `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `docs/interop-matrix.md`, and `docs/coverage-matrix.md`. |
| TG-010 | P2 | open | Define and implement a real SMB1/CIFS interop policy. Decide whether real SMB1 is in scope; if yes, add an opt-in, isolated harness against an SMB1-capable peer. If no, document that full interoperability excludes SMB1 real-peer claims. | `docs/coverage-matrix.md`, `docs/interop-matrix.md`, `README.md`, and `OPENCIFS.md` consistently state the SMB1 policy; any SMB1 real-peer evidence is opt-in and clearly separated from default release gates. | Update docs first; only add `eng/` SMB1 harnesses if the project chooses to support real SMB1 peers. |
| TG-011 | P2 | open | Add Kerberos SMB interoperability coverage after native Kerberos support exists. Test domain-backed authentication against Windows and, if feasible, Samba AD. | Coverage rows move from Kerberos backlog to implemented or shared as appropriate; interop evidence records domain setup, principal, dialect, signing, encryption, and failure modes without storing secrets. | Implement Kerberos support first; then add an `eng/` harness, update `docs/coverage-matrix.md`, `docs/interop-matrix.md`, and secret-handling docs. |
| TG-012 | P2 | open | Keep evidence freshness enforceable. Decide the maximum acceptable age for external interop evidence, then add validation that fails when passed rows exceed that age. | `eng/validate-release-artifacts.ps1` enforces the chosen freshness policy or exact `AsOfDate`; `TESTING_GAPS.md`, `docs/interop-matrix.md`, and `docs/coverage-matrix.md` all show current dates after each evidence refresh. | Update `eng/validate-release-artifacts.ps1`; document the cadence in this file and the affected matrix rows. |

Suggested execution order:
1. Close TG-001, TG-002, and TG-003 first because they decide whether the existing release claim is complete enough to trust.
2. Close TG-004 through TG-009 next to broaden real-peer and advanced SMB coverage.
3. Treat TG-010 and TG-011 as explicit scope decisions before committing engineering time to legacy SMB1 or enterprise Kerberos environments.

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
