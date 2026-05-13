# Testing Gaps

Reviewed on 2026-05-13.

Bottom line: the repository has strong internal coverage and bounded external interoperability coverage, but it is not yet at full interoperability testing.

## 1. OpenCIFS client against a live Docker CIFS server

Current state: partially covered.

What exists:
- `eng/run-samba-interop.ps1` runs `OpenCIFS.Client` against a Dockerized Samba server.
- `eng/run-windows-server-interop.ps1` can run `OpenCIFS.TestClient` against a pre-provisioned live Windows SMB share and write `artifacts/windows-server-interop/windows-server-interop.json`.
- `docs/interop-matrix.md` records passing evidence for `OpenCIFS.Client -> Samba server` on SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- The current Docker peer is Samba `smbd` 4.17.12 on Debian bookworm.

Gaps:
- Only one live Docker server implementation is covered: Samba.
- No checked-in passing Windows server evidence exists yet for `OpenCIFS.Client`; `docs/interop-matrix.md` marks the Windows server row as harness-ready but not run.
- No additional server products or versions are covered.
- Coverage is bounded smoke/deeper-smoke, not a broad command-by-command interoperability matrix.
- External durable-handle v2 coverage is still backlog.
- Broader SMB 3.x external coverage is still backlog.
- SMB 3.1.1 external coverage is preview-only through `-IncludeSmb311Preview` and is not part of the default release-gated evidence.
- The release validator still only requires `smb2002`, `smb21`, and `smb302` for external interop artifacts.

## 2. OpenCIFS client against an OpenCIFS server

Current state: strongly covered for internal managed-path regression, but not enough to claim full interoperability.

What exists:
- `src/OpenCIFS.Client.Tests.Shared/ClientTestSupport.cs` starts a real `OpenCifsDirectTcpServer` on loopback and exercises the client over direct TCP.
- `docs/coverage-matrix.md` records extensive live-listener managed client coverage over `OpenCifsDirectTcpServer`.
- `src/OpenCIFS.Interop.Tests.Shared/InteropTestSuites.cs` provides broad loopback suites for negotiate, session/tree, file I/O, metadata, locking, notify, oplocks, leases, durable handles, compound requests, and IOCTLs.
- `eng/run-test-console-smoke.ps1` runs `OpenCIFS.TestClient` and `OpenCIFS.TestServer` as separate processes and drives end-to-end operations over loopback.
- `eng/run-managed-interop.ps1` runs `OpenCIFS.TestClient` against `OpenCIFS.TestServer` as separate processes across SMB 2.0.2, SMB 2.1, and SMB 3.0.2 and writes `artifacts/managed-interop/managed-interop.json`.

Gaps:
- Much of the dedicated `Interop` suite is in-process loopback coverage, not a socket-level two-process interop harness.
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
- SMB 3.1.1 external coverage is preview-only through `-IncludeSmb311Preview` and is not part of the default release-gated evidence.

## 4. OpenCIFS server against an OpenCIFS client

Current state: strongly covered for internal managed-path regression, but not enough to claim full interoperability.

What exists:
- `src/OpenCIFS.Client.Tests.Shared/ClientTestSupport.cs` starts `OpenCifsDirectTcpServer` and drives the managed client against it over real loopback TCP.
- `docs/coverage-matrix.md` records extensive direct-TCP managed client coverage against the managed server.
- `eng/run-test-console-smoke.ps1` runs `OpenCIFS.TestClient` against `OpenCIFS.TestServer` as separate executables.
- `eng/run-managed-interop.ps1` records a dialect-by-dialect managed client/server artifact for SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- `src/OpenCIFS.Interop.Tests.Shared/InteropTestSuites.cs` covers a broad set of managed loopback protocol behaviors.

Gaps:
- There is no released-binary or cross-version managed client/server compatibility matrix.
- The strongest managed-path suites are still same-repo and mostly same-build coverage.
- There is no Dockerized managed client or server lane for reproducible OpenCIFS-to-OpenCIFS interoperability runs.

## Cross-cutting gaps

### External interop is not in always-on CI

- `.github/workflows/ci.yaml` runs build, Touchstone, and framework tests only.
- `.github/workflows/external-interop.yaml` now runs `eng/run-integration-gates.ps1` on a scheduled and manually triggered self-hosted Windows runner labeled `external-interop`.
- The external interop harnesses are composed locally by `eng/run-integration-gates.ps1` and `eng/run-release-gates.ps1`, but they are not part of the default CI signal.

Impact:
- External interop has a GitHub Actions entrypoint, but the signal depends on provisioning the required self-hosted runner with Docker, Python, Windows SMB client support, and the project prerequisites.

### Evidence is stale relative to the current date

- The interop matrix rows are last verified on 2026-04-30.
- The current review date is 2026-05-13.
- `eng/validate-release-artifacts.ps1` enforces exact `AsOfDate` freshness for passed `docs/interop-matrix.md` rows and non-`n/a` verification dates in `docs/coverage-matrix.md`.

Impact:
- The repository does not currently carry same-day or near-current external interop evidence.

### SMB 3.1.1 preview coverage is intentionally opt-in

- `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, and `eng/run-windows-client-interop.ps1` default to SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- Those scripts can include SMB 3.1.1 only when called with `-IncludeSmb311Preview`.
- `eng/run-nightly-interop.ps1` explicitly passes `-IncludeSmb311Preview` so the nightly lane can continue exercising preview coverage.
- `eng/validate-release-artifacts.ps1` intentionally requires only `smb2002`, `smb21`, and `smb302` for release artifacts.

Impact:
- SMB 3.1.1 external interop remains preview evidence, not a release-gated interoperability claim.

### Windows server interoperability is still missing

- `eng/run-windows-server-interop.ps1` now provides the harness for `OpenCIFS.Client -> Windows server`.
- `docs/interop-matrix.md` marks the row as harness-ready but not run.
- `docs/coverage-matrix.md` also calls out `OpenCIFS.Client` to Windows server coverage as backlog.

Impact:
- There is still no checked-in passing evidence that the managed client interoperates with a live Windows SMB server.

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

### SMB1/CIFS real interoperability is intentionally out of current claim scope

- The repository has SMB1 codec and bootstrap coverage, but real SMB1 client/server interop remains backlog.
- Current "full interoperability" claims for release-gated evidence exclude real SMB1 peers until the project deliberately implements and enables an isolated opt-in SMB1 harness.

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
| TG-001 | P0 | in_progress | Add `OpenCIFS.Client -> Windows server` interop coverage. `eng/run-windows-server-interop.ps1` now targets a pre-provisioned live Windows SMB share, runs the managed test client for SMB 2.0.2, SMB 2.1, and SMB 3.0.2, and writes JSON artifacts with environment details, dialect IDs, pass/fail state, and exercised operations. | Complete when the harness has been run against a live Windows SMB server, `docs/interop-matrix.md` records pass evidence and a verification date, `docs/coverage-matrix.md` records Windows-server verification for the managed client path, and release validation includes the artifact if this becomes release-gated. | Added `eng/run-windows-server-interop.ps1` and updated `docs/interop-matrix.md`; still needs a provisioned Windows SMB target and passing evidence refresh. |
| TG-002 | P0 | completed | Decide the SMB 3.1.1 preview interop policy and align scripts, docs, and gates. SMB 3.1.1 is preview-only and non-release-gated; release interop scripts default to SMB 2.0.2, SMB 2.1, and SMB 3.0.2, while nightly explicitly opts into `-IncludeSmb311Preview`. | `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `eng/run-nightly-interop.ps1`, and `eng/validate-release-artifacts.ps1` agree that `smb311` is preview evidence only. | Completed in `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `eng/run-nightly-interop.ps1`, and this register. |
| TG-003 | P0 | in_progress | Put external interop into recurring CI. `.github/workflows/external-interop.yaml` now provides scheduled and manual execution on a self-hosted Windows runner labeled `external-interop`, runs `eng/run-integration-gates.ps1`, optionally runs SMB 3.1.1 preview lanes, and uploads interop artifacts. | Complete when the repository has a provisioned runner with Docker, Python, Windows SMB client support, and scheduled runs producing current artifacts that can refresh the matrix dates. | Added `.github/workflows/external-interop.yaml`; still needs runner provisioning and first successful scheduled evidence refresh. |
| TG-004 | P1 | open | Add Linux kernel CIFS client coverage against `Sample.OpenCifsServer`. Use a Docker or privileged Linux runner lane with `cifs-utils`/`mount.cifs`, mount the sample share, and exercise create, read, write, metadata, rename, delete, lock conflict, and dialect pinning where supported. | `docs/interop-matrix.md` has a `Sample.OpenCifsServer | Linux kernel CIFS client` row with pass evidence and a current date; the artifact records kernel, cifs-utils, mount options, dialect, and operation results. | Add Docker or workflow support under `eng/docker/` and `eng/`; update `docs/interop-matrix.md` and `docs/coverage-matrix.md`; consider `eng/validate-release-artifacts.ps1` once stable. |
| TG-005 | P1 | completed | Add a standard two-process OpenCIFS-to-OpenCIFS interop harness. `eng/run-managed-interop.ps1` runs `OpenCIFS.TestServer` and `OpenCIFS.TestClient` as separate processes across SMB 2.0.2, SMB 2.1, and SMB 3.0.2. | `OpenCIFS.Client -> OpenCIFS.TestServer` and `OpenCIFS.TestServer -> OpenCIFS.TestClient` have artifact-backed rows in `docs/interop-matrix.md`; the harness is callable from integration gates; release validation requires `artifacts/managed-interop/managed-interop.json`. | Completed in `eng/run-managed-interop.ps1`, `eng/run-integration-gates.ps1`, `eng/validate-release-artifacts.ps1`, and `docs/interop-matrix.md`. |
| TG-006 | P1 | open | Add managed client/server cross-version compatibility coverage. Test current client against the previous released server and current server against the previous released client, using published packages or release artifacts instead of same-commit projects. | A cross-version compatibility artifact exists with package or commit versions; `docs/interop-matrix.md` records N-to-N-1 coverage; release notes can cite explicit compatibility evidence. | Add an `eng/` harness that restores or downloads released packages; update `docs/interop-matrix.md`; add artifact checks if this becomes release-gated. |
| TG-007 | P1 | open | Expand peer diversity beyond the current Samba 4.17.12 image. Add at least one additional Samba version or distribution image and record exact versions in evidence. | `docs/interop-matrix.md` distinguishes each Samba target version or records a multi-version matrix; artifacts include `smbd`, `smbclient`, OS, and Docker image identifiers. | Add Dockerfiles or build arguments under `eng/docker/samba-interop/`; update `eng/run-samba-interop.ps1`, `docs/interop-matrix.md`, and `docs/coverage-matrix.md`. |
| TG-008 | P1 | open | Add external DFS interoperability. Exercise managed DFS referral handling against a real Windows or Samba DFS namespace, including referral retrieval, cache behavior, and at least one redirected tree connect path. | `docs/coverage-matrix.md` no longer marks external DFS interop as backlog; `docs/interop-matrix.md` has a DFS row with artifact-backed pass evidence. | Add an interop script under `eng/`; update `docs/coverage-matrix.md`, `docs/interop-matrix.md`, and release validation if required. |
| TG-009 | P1 | open | Add external durable-handle v2 and broader SMB 3.x behavior coverage. Extend the external interop artifacts to include durable create, disconnect, reconnect, preserved byte-range lock behavior, and lease/oplock behavior where the peer supports it. | Samba, Windows-client, and Python-client artifacts explicitly report durable-handle v2 or a peer-capability skip reason; matrix notes stop calling durable-handle v2 a blanket backlog item. | Update `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `docs/interop-matrix.md`, and `docs/coverage-matrix.md`. |
| TG-010 | P2 | completed | Define and implement a real SMB1/CIFS interop policy. Real SMB1 peer interoperability is excluded from current release-gated interoperability claims; any future real SMB1 testing must be isolated, opt-in, and separate from default gates. | `docs/coverage-matrix.md`, `docs/interop-matrix.md`, `README.md`, `OPENCIFS.md`, and this file consistently state that SMB1 codec/bootstrap work exists but real SMB1 peer interop remains outside the current claim scope. | Completed in docs; add an `eng/` SMB1 harness only if the project deliberately expands scope later. |
| TG-011 | P2 | open | Add Kerberos SMB interoperability coverage after native Kerberos support exists. Test domain-backed authentication against Windows and, if feasible, Samba AD. | Coverage rows move from Kerberos backlog to implemented or shared as appropriate; interop evidence records domain setup, principal, dialect, signing, encryption, and failure modes without storing secrets. | Implement Kerberos support first; then add an `eng/` harness, update `docs/coverage-matrix.md`, `docs/interop-matrix.md`, and secret-handling docs. |
| TG-012 | P2 | completed | Keep evidence freshness enforceable. The current policy is exact `AsOfDate` matching for passed interop rows and non-`n/a` coverage verification dates during release validation. | `eng/validate-release-artifacts.ps1` rejects stale passed matrix rows relative to its `-AsOfDate` value; evidence refreshes must update `docs/interop-matrix.md` and `docs/coverage-matrix.md` in the same change as the artifacts. | Completed in `eng/validate-release-artifacts.ps1` and documented in this register. |

Suggested execution order:
1. Close TG-001 next and finish TG-003 runner provisioning because Windows-server coverage and recurring external CI are still the highest-value release-signal gaps.
2. Close TG-004 and TG-006 through TG-009 next to broaden real-peer, cross-version, and advanced SMB coverage.
3. Treat TG-011 as an explicit scope decision before committing engineering time to enterprise Kerberos environments.

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
