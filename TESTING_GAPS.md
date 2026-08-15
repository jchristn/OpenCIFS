# Testing Gaps

Reviewed on 2026-05-18.

Bottom line: OpenCIFS `0.1.0` is alpha software. The repository has strong internal coverage and bounded external interoperability coverage, but thorough or exhaustive compatibility testing has not yet been completed.

## 1. OpenCIFS client against a live Docker CIFS server

Current state: partially covered.

What exists:
- `eng/run-samba-interop.ps1` runs `OpenCIFS.Client` against a Dockerized Samba server.
- `eng/run-samba-interop.ps1` now accepts explicit Samba image, Dockerfile, and peer-label parameters.
- `eng/run-samba-peer-matrix.ps1` can run the Samba interop harness against the checked-in Bookworm and Trixie Docker contexts and preserve per-peer artifacts under `artifacts/samba-peer-matrix`.
- `eng/run-windows-server-interop.ps1` can run `OpenCIFS.TestClient` against a pre-provisioned live Windows SMB share and write `artifacts/windows-server-interop/windows-server-interop.json`.
- `eng/run-local-windows-server-interop.ps1` can provision a temporary local Windows SMB share plus local account from an elevated PowerShell session, delegate to `eng/run-windows-server-interop.ps1`, and clean up afterward.
- `docs/interop-matrix.md` records passing evidence for `OpenCIFS.Client -> Samba server` on SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- The checked-in Docker peer matrix now includes Samba `smbd` 4.17.12 on Debian bookworm and 4.22.8 on Debian trixie.

Gaps:
- Only one live Docker server implementation family is covered: Samba, now with Bookworm and Trixie peer-matrix evidence.
- No checked-in passing Windows server evidence exists yet for `OpenCIFS.Client`; `docs/interop-matrix.md` still marks the Windows server row as not run because the new local helper has only been validated through its non-elevated guard path in this session.
- No additional server products beyond Samba are covered by passing checked-in evidence.
- Coverage is bounded smoke/deeper-smoke, not a broad command-by-command interoperability matrix.
- The harness artifacts now record external durable-handle v2 outcome or skip data, and the 2026-05-15 Bookworm and Trixie Samba artifacts now document a bounded unsupported durable-handle v2 outcome rather than leaving the area unclassified.
- Advanced SMB 3.x outcome reporting is now present in the external harness artifacts, and the 2026-05-15 Bookworm and Trixie reruns now show passing oplock and lease outcomes while durable-handle v2 remains unsupported on the checked-in Samba peers.
- SMB 3.1.1 external coverage is preview-only through `-IncludeSmb311Preview` and is not part of the default release-gated evidence.
- The release validator still only requires `smb2002`, `smb21`, and `smb302` for external interop artifacts.

## 2. OpenCIFS client against an OpenCIFS server

Current state: strongly covered for internal managed-path regression, but not enough to claim full interoperability.

What exists:
- `src/OpenCIFS.Test.Shared/Client/ClientTestSupport.cs` starts a real `OpenCifsDirectTcpServer` on loopback and exercises the client over direct TCP.
- `docs/coverage-matrix.md` records extensive live-listener managed client coverage over `OpenCifsDirectTcpServer`.
- `src/OpenCIFS.Test.Shared/Interop/InteropTestSuites.cs` provides broad loopback suites for negotiate, session/tree, file I/O, metadata, locking, notify, oplocks, leases, durable handles, compound requests, and IOCTLs.
- `eng/run-test-console-smoke.ps1` runs `OpenCIFS.TestClient` and `OpenCIFS.TestServer` as separate processes and drives end-to-end operations over loopback.
- `eng/run-managed-interop.ps1` runs `OpenCIFS.TestClient` against `OpenCIFS.TestServer` as separate processes across SMB 2.0.2, SMB 2.1, and SMB 3.0.2 and writes `artifacts/managed-interop/managed-interop.json`.
- `eng/run-cross-version-managed-interop.ps1` now runs a bounded N-to-N-1 package-feed matrix, and `artifacts/cross-version-managed-interop/cross-version-managed-interop.json` now records a 2026-05-15 local feed run using package version `0.0.0-git.4af1f6d` built from commit `4af1f6d`.

Gaps:
- Much of the dedicated `Interop` suite is in-process loopback coverage, not a socket-level two-process interop harness.
- There is no released client N against released server N-1 or N+1 matrix; the current cross-version evidence is a bounded local package-feed N-to-N-1 run.
- There is no Dockerized OpenCIFS server harness used as a standard interop target.
- There is no long-running two-process managed client/server interoperability soak comparable to the external nightly composition.
- Because both ends come from the same codebase and same commit, this is strong regression coverage but weaker evidence of independent interoperability behavior.

## 3. OpenCIFS server against a live Docker CIFS client

Current state: partially covered.

What exists:
- `eng/run-samba-interop.ps1` runs Dockerized Samba `smbclient` against `Sample.OpenCifsServer`.
- `eng/run-samba-peer-matrix.ps1` can repeat the Samba client and server interop run against multiple Debian-based Samba image definitions.
- `eng/run-linux-cifs-interop.ps1` can run a privileged Dockerized Linux kernel CIFS client with `cifs-utils`/`mount.cifs` against `Sample.OpenCifsServer`.
- `docs/interop-matrix.md` records passing evidence for `Sample.OpenCifsServer -> Samba client` on SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- `docs/interop-matrix.md` now also records passing Linux kernel CIFS evidence for SMB 2.1 and SMB 3.0.2 on the current WSL2/Docker Desktop host, and the artifact now carries an explicit `smb2002` host-policy skip entry instead of silently omitting that dialect.
- The checked-in Docker peer matrix now includes Samba `smbclient` 4.17.12 on Debian bookworm and 4.22.8 on Debian trixie.

Gaps:
- Live Docker client coverage now spans Samba userland plus the Linux kernel CIFS client, but it still represents mostly the Linux/Samba ecosystem.
- SMB 2.0.2 remains host-policy-blocked on the current WSL2/Docker Desktop kernel before any OpenCIFS traffic reaches the server: both `Sample.OpenCifsServer` and Samba `smbd` produce the same Linux kernel diagnostic, `vers=2.0 mount not permitted when legacy dialects disabled`, so oldest-dialect Linux-kernel evidence still needs a host that permits `vers=2.0` mounts.
- Coverage is bounded smoke/deeper-smoke, not a broad command-by-command interoperability matrix.
- The harness artifacts now record external durable-handle v2 and broader SMB 3.x outcome or skip data. For the bounded Samba-client lane, the 2026-05-15 Bookworm and Trixie reruns now record explicit SMB 3.x skip reasons because `smbclient` does not surface reconnect tokens or break notifications through this workflow, while the reciprocal `OpenCIFS.Client -> Samba` artifacts now document a bounded unsupported durable-handle v2 outcome.
- SMB 3.1.1 external coverage is preview-only through `-IncludeSmb311Preview` and is not part of the default release-gated evidence.

## 4. OpenCIFS server against an OpenCIFS client

Current state: strongly covered for internal managed-path regression, but not enough to claim full interoperability.

What exists:
- `src/OpenCIFS.Test.Shared/Client/ClientTestSupport.cs` starts `OpenCifsDirectTcpServer` and drives the managed client against it over real loopback TCP.
- `docs/coverage-matrix.md` records extensive direct-TCP managed client coverage against the managed server.
- `eng/run-test-console-smoke.ps1` runs `OpenCIFS.TestClient` against `OpenCIFS.TestServer` as separate executables.
- `eng/run-managed-interop.ps1` records a dialect-by-dialect managed client/server artifact for SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- `eng/run-cross-version-managed-interop.ps1` now records a bounded N-to-N-1 package-feed matrix for `current client -> previous server` and `previous client -> current server`.
- `src/OpenCIFS.Test.Shared/Interop/InteropTestSuites.cs` covers a broad set of managed loopback protocol behaviors.

Gaps:
- There is no released-binary managed client/server compatibility matrix; the current evidence is a bounded local package-feed N-to-N-1 run.
- The strongest managed-path suites are still same-repo and mostly same-build coverage.
- There is no Dockerized managed client or server lane for reproducible OpenCIFS-to-OpenCIFS interoperability runs.

## Cross-cutting gaps

### External interop is not in recurring automation

- The checked-in GitHub Actions workflow assets were removed after repeated failures.
- The external interop harnesses are still composed locally by `eng/run-integration-gates.ps1` and `eng/run-release-gates.ps1`.
- Recurring execution now depends on maintainers wiring those scripts into a stable local or hosted scheduler outside the current repository contents.

Impact:
- External interop currently depends on manual or separately managed automation, so freshness and regression signal will drift unless maintainers restore a stable execution path.

### Evidence freshness is aligned locally but still needs automation

- The required passed interop rows and non-`n/a` coverage dates were refreshed locally to 2026-05-15.
- `eng/validate-release-artifacts.ps1` still enforces exact `AsOfDate` freshness for passed `docs/interop-matrix.md` rows and non-`n/a` verification dates in `docs/coverage-matrix.md`.
- The remaining freshness risk is operational rather than structural: without TG-003 recurring automation, the next evidence refresh is still manual.

Impact:
- A release-validator run for 2026-05-15 can now pass once the docs and artifacts remain in sync, but freshness will drift again unless recurring external interop automation is brought online.

### SMB 3.1.1 preview coverage is intentionally opt-in

- `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, and `eng/run-windows-client-interop.ps1` default to SMB 2.0.2, SMB 2.1, and SMB 3.0.2.
- Those scripts can include SMB 3.1.1 only when called with `-IncludeSmb311Preview`.
- `eng/run-nightly-interop.ps1` explicitly passes `-IncludeSmb311Preview` so the nightly lane can continue exercising preview coverage.
- `eng/validate-release-artifacts.ps1` intentionally requires only `smb2002`, `smb21`, and `smb302` for release artifacts.

Impact:
- SMB 3.1.1 external interop remains preview evidence, not a release-gated interoperability claim.

### Windows server interoperability is still missing

- `eng/run-windows-server-interop.ps1` now provides the harness for `OpenCIFS.Client -> Windows server`.
- `eng/run-local-windows-server-interop.ps1` now provides a no-external-service Windows path by creating a temporary local share and account, invoking the generic harness against `127.0.0.1`, and cleaning up afterward.
- `docs/interop-matrix.md` marks the row as harness-ready but not run.
- `docs/coverage-matrix.md` also calls out `OpenCIFS.Client` to Windows server coverage as backlog.

Impact:
- There is still no checked-in passing evidence that the managed client interoperates with a live Windows SMB server; the remaining step is an elevated local run or another live Windows SMB target.

### Peer diversity is limited

- External server-side coverage now includes Samba `smbclient`, the Linux kernel CIFS client on SMB 2.1/3.0.2, and the built-in Windows client against the sample server.
- External client-side Docker coverage now includes both Samba `smbclient` and a Debian bookworm Linux kernel CIFS client lane.
- The checked-in peer matrix now spans Samba 4.17.12 on Bookworm and 4.22.8 on Trixie, but the overall peer set is still concentrated in Samba/Linux plus the built-in Windows client and Python `smbprotocol`.

Impact:
- The current interop story is bounded vendor coverage, not broad ecosystem coverage.

### DFS external interoperability is now bounded to Samba coverage

- `docs/interop-matrix.md` and `docs/coverage-matrix.md` now record 2026-05-15 pass evidence for `OpenCIFS.Client -> external DFS namespace` against a Dockerized Samba standalone DFS root and redirected storage share.
- `eng/run-samba-dfs-interop.ps1` now provisions that Samba DFS namespace locally and delegates the actual client validation to `eng/run-dfs-interop.ps1`.
- Windows DFS namespaces, multi-target referrals, and broader DFS peer diversity remain backlog.

Impact:
- Managed DFS behavior is now proven against a real external Samba DFS peer, but broader DFS peer diversity remains backlog.

### Durable and advanced SMB 3.x external interoperability is incomplete

- The external Python, Samba, and Windows harness artifacts now record structured advanced SMB 3.x durable-handle v2 or skip data, and the 2026-05-15 Bookworm and Trixie Samba reruns now show passing SMB 3.0.2 oplock and lease outcomes plus a documented unsupported durable-handle v2 outcome: the peer grants reconnect state, but detached competing-open lock semantics are not preserved and reconnect create returns `STATUS_OBJECT_NAME_NOT_FOUND`.
- Broader SMB 3.x nightly or external coverage remains backlog.
- SMB 3.1.1 external interop remains backlog and is still preview-only.

Impact:
- Advanced reconnect, lease, and modern SMB 3.x behavior is now classified in the checked-in external evidence, but durable-handle v2 still lacks an external passing peer.

### SMB1/CIFS real interoperability is intentionally out of current claim scope

- The repository has SMB1 codec and bootstrap coverage, but real SMB1 client/server interop remains backlog.
- Current "full interoperability" claims for release-gated evidence exclude real SMB1 peers until the project deliberately implements and enables an isolated opt-in SMB1 harness.

Impact:
- If "full CIFS interoperability" includes real SMB1 peers, the project is not there yet.

### Kerberos interoperability is still backlog

- The coverage matrix marks native Kerberos for SMB as backlog.
- The current client credential surface now has an explicit authentication-mechanism selector, and the client can advertise Kerberos SPNEGO OIDs when explicitly requested, but it still stops at a bounded `Kerberos session setup is not implemented yet.` failure before any real Kerberos token exchange.
- The current server options surface now has an explicit authentication-mechanism selector, and the server can recognize a Kerberos SPNEGO offer and return `STATUS_NOT_SUPPORTED` cleanly when configured for Kerberos, but it still derives SMB session keys only from verified NTLMv2 response material.
- There is no GSS-API/SSPI-backed Kerberos token flow or exported Kerberos session-key plumbing for SMB signing and encryption yet.

Impact:
- Full enterprise interoperability is not yet covered, and external Kerberos harness work is still premature until the core token-generation, token-verification, and key-derivation path exists.

## Actionable developer work queue

Keep this section as the execution register for the gaps above. When an item lands, update its status, the linked matrix rows, the release validator if the evidence became required, and the evidence date. If a run is intentionally skipped, record the reason in the relevant matrix row instead of deleting the item.

| ID | priority | status | action | done when | primary files or commands to update |
| --- | --- | --- | --- | --- | --- |
| TG-001 | P0 | in_progress | Add `OpenCIFS.Client -> Windows server` interop coverage. `eng/run-windows-server-interop.ps1` now targets a pre-provisioned live Windows SMB share, runs the managed test client for SMB 2.0.2, SMB 2.1, and SMB 3.0.2, and writes JSON artifacts with environment details, dialect IDs, pass/fail state, and exercised operations. `eng/run-local-windows-server-interop.ps1` now provides the local no-external-service path by provisioning a temporary local share plus account from an elevated PowerShell session, delegating to the generic harness, and cleaning up afterward. `eng/run-integration-gates.ps1` now auto-invokes the generic lane when `OPENCIFS_WINDOWS_SERVER_*` environment variables are fully configured, so the live Windows-server harness can participate in recurring interop runs without exposing secrets on the command line. | Complete when the harness has been run against a live Windows SMB server, `docs/interop-matrix.md` records pass evidence and a verification date, `docs/coverage-matrix.md` records Windows-server verification for the managed client path, and release validation includes the artifact if this becomes release-gated. | Added `eng/run-windows-server-interop.ps1` plus `eng/run-local-windows-server-interop.ps1`, wired the generic lane into `eng/run-integration-gates.ps1`, and documented the environment-driven and local elevated paths in `README.md`. The helper currently validates its elevation guard in a non-admin session; a passing elevated local run or another live Windows SMB target is still needed. |
| TG-002 | P0 | completed | Decide the SMB 3.1.1 preview interop policy and align scripts, docs, and gates. SMB 3.1.1 is preview-only and non-release-gated; release interop scripts default to SMB 2.0.2, SMB 2.1, and SMB 3.0.2, while nightly explicitly opts into `-IncludeSmb311Preview`. | `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `eng/run-nightly-interop.ps1`, and `eng/validate-release-artifacts.ps1` agree that `smb311` is preview evidence only. | Completed in `eng/run-real-client-interop.ps1`, `eng/run-samba-interop.ps1`, `eng/run-windows-client-interop.ps1`, `eng/run-nightly-interop.ps1`, and this register. |
| TG-003 | P0 | in_progress | Restore external interop into recurring automation once a stable execution environment exists. The harness composition remains in `eng/run-integration-gates.ps1`, with optional `OPENCIFS_ENABLE_CROSS_VERSION_INTEROP`, `OPENCIFS_DFS_*`, `OPENCIFS_ENABLE_LINUX_CIFS_INTEROP` plus `OPENCIFS_LINUX_CIFS_IMAGE_NAME`, and `OPENCIFS_WINDOWS_SERVER_*` inputs enabling the cross-version, DFS, Linux-CIFS, and Windows-server lanes. The previously checked-in GitHub workflow assets were removed after repeated failures, so this work item is now about reintroducing dependable automation rather than keeping broken CI definitions around. | Complete when maintainers have a stable scheduled or otherwise recurring execution path that can run the external harnesses with Docker, Python, Windows SMB client support, and current artifact refreshes that can update the matrix dates. | The current repository keeps the external harness composition in `eng/run-integration-gates.ps1` and `eng/run-release-gates.ps1`, and local `2026-05-15` evidence refreshes prove the harness composition. Recurring automation must be reintroduced separately when a stable host and operating model are available. |
| TG-004 | P1 | completed | Add Linux kernel CIFS client coverage against `Sample.OpenCifsServer`. `eng/run-linux-cifs-interop.ps1` now builds a Dockerized `cifs-utils` image, starts `Sample.OpenCifsServer`, and uses privileged `mount.cifs` lanes to exercise mount, create, read, write, large-file copy, rename, non-empty-directory delete rejection, and cleanup. `eng/run-integration-gates.ps1` now auto-invokes that lane when `OPENCIFS_ENABLE_LINUX_CIFS_INTEROP=true`, so privileged hosts can include the Linux kernel CIFS matrix in recurring interop runs while normal hosts still skip it safely. | Complete when the harness has passing evidence on a Docker host that supports privileged CIFS mounts, `docs/interop-matrix.md` has a `Sample.OpenCifsServer | Linux kernel CIFS client` pass row with a current date, and the artifact records kernel, cifs-utils, mount options, dialect, and operation results. Byte-range lock-conflict coverage can be added after the mount path is stable. | Completed with refreshed 2026-05-15 bookworm `mount.cifs` 7.0 evidence in `artifacts/linux-cifs-interop/linux-cifs-interop.json` and `artifacts/linux-cifs-interop/linux-cifs-environment.json`, plus harness fixes for stable LF Bash execution, Linux-kernel rename payload tolerance, rename destination resolution, `IPC$` exposure on the sample server, and explicit `smb2002` host-policy skip recording on WSL2/Docker Desktop hosts. `eng/validate-release-artifacts.ps1` now accepts the documented skipped lane when it records a structured `skip_reason`. |
| TG-005 | P1 | completed | Add a standard two-process OpenCIFS-to-OpenCIFS interop harness. `eng/run-managed-interop.ps1` runs `OpenCIFS.TestServer` and `OpenCIFS.TestClient` as separate processes across SMB 2.0.2, SMB 2.1, and SMB 3.0.2. | `OpenCIFS.Client -> OpenCIFS.TestServer` and `OpenCIFS.TestServer -> OpenCIFS.TestClient` have artifact-backed rows in `docs/interop-matrix.md`; the harness is callable from integration gates; release validation requires `artifacts/managed-interop/managed-interop.json`. | Completed in `eng/run-managed-interop.ps1`, `eng/run-integration-gates.ps1`, `eng/validate-release-artifacts.ps1`, and `docs/interop-matrix.md`, with refreshed 2026-05-15 evidence in `artifacts/managed-interop/managed-interop.json`. |
| TG-006 | P1 | completed | Add managed client/server cross-version compatibility coverage. `eng/run-cross-version-managed-interop.ps1` now restores previous `OpenCIFS.Client` and `OpenCIFS.Server` packages from a configurable package source, generates temporary current-project and previous-package consumers, runs `current client -> previous server` plus `previous client -> current server` across SMB 2.0.2, SMB 2.1, and SMB 3.0.2, and writes `artifacts/cross-version-managed-interop/cross-version-managed-interop.json`. `eng/run-integration-gates.ps1` now auto-invokes that lane when `OPENCIFS_ENABLE_CROSS_VERSION_INTEROP=true`. | A cross-version compatibility artifact exists with package or commit versions; `docs/interop-matrix.md` records N-to-N-1 coverage; release notes can cite explicit compatibility evidence. | Completed with a refreshed 2026-05-15 local feed run built from commit `4af1f6d`, recorded in `artifacts/cross-version-package-feed/feed-metadata.json` and `artifacts/cross-version-managed-interop/cross-version-managed-interop.json`. Public released-package evidence can replace the local feed later without reopening the item. |
| TG-007 | P1 | completed | Expand peer diversity beyond the current Samba 4.17.12 image. The Samba harness now accepts image/Dockerfile/peer-label inputs, and `eng/run-samba-peer-matrix.ps1` can run Bookworm and Trixie Debian-based Samba peers while preserving per-peer artifacts. | Complete when the additional peer run has passing evidence checked in or attached, `docs/interop-matrix.md` distinguishes each Samba target version or records a multi-version matrix, and artifacts include `smbd`, `smbclient`, OS, and Docker image identifiers. | Completed with refreshed 2026-05-15 Bookworm 4.17.12 and Trixie 4.22.8 peer-matrix reruns preserved under `artifacts/samba-peer-matrix/debian-bookworm` and `artifacts/samba-peer-matrix/debian-trixie`, plus multi-version notes in `docs/interop-matrix.md`. |
| TG-008 | P1 | completed | Add external DFS interoperability. `eng/run-dfs-interop.ps1` now targets an external DFS namespace path, fetches referrals through the managed client, reconnects to the redirected storage target, and exercises directory-create, file-write, enumerate, read, rename, delete, and cleanup against that target while writing `artifacts/dfs-interop/dfs-interop.json`. `eng/run-samba-dfs-interop.ps1` now provisions a Dockerized Samba standalone DFS root plus redirected storage share and delegates the actual client validation to the generic DFS harness, while `eng/run-integration-gates.ps1` continues to auto-invoke the generic lane when `OPENCIFS_DFS_*` environment variables are fully configured. | `docs/coverage-matrix.md` no longer marks external DFS interop as backlog; `docs/interop-matrix.md` has a DFS row with artifact-backed pass evidence. | Completed with refreshed 2026-05-15 Samba DFS evidence in `artifacts/dfs-interop/dfs-interop.json`, `artifacts/dfs-interop/dfs-environment.json`, `artifacts/dfs-interop/samba-dfs-server.log`, and `artifacts/dfs-interop/samba-dfs-versions.txt`. The implementation work also fixed external DFS referral parsing for Samba V2 payloads that place strings beyond the fixed entry body, relaxed the cache expectation after an explicit referral fetch, and taught the client compounded-response path to tolerate zero-credit non-final synchronous entries so redirected Samba writes succeed across SMB 2.0.2, SMB 2.1, and SMB 3.0.2. |
| TG-009 | P1 | completed | Add external durable-handle v2 and broader SMB 3.x behavior coverage. The external Python, Samba, and Windows harness artifacts now record structured `advanced_smb3` outcome data on SMB 3.x lanes, and the `OpenCIFS.Client -> Samba` console now attempts durable create, abrupt disconnect, durable reconnect, preserved byte-range lock behavior, exclusive oplock break, and lease break against Samba while the other external lanes record explicit skip reasons when their bounded harnesses do not surface reconnect tokens or break notifications. | Samba, Windows-client, and Python-client artifacts explicitly report advanced SMB 3.x durable-handle v2 or skip data, at least one external peer has checked-in pass evidence or a documented unsupported outcome for durable-handle v2, and the matrix notes no longer describe the entire area as an undifferentiated backlog item. | Completed with refreshed 2026-05-15 Bookworm 4.17.12 and Trixie 4.22.8 reruns in `artifacts/samba-interop/open-cifs-client-to-samba.json` and `artifacts/samba-peer-matrix/*/open-cifs-client-to-samba.json`: oplock and lease now pass, while durable-handle v2 is explicitly recorded as unsupported because the peer grants reconnect state but does not preserve detached competing-open lock semantics and rejects the reconnect create with `STATUS_OBJECT_NAME_NOT_FOUND`. Windows and Python lanes continue to report bounded skip reasons where their workflows do not surface reconnect tokens or break notifications. |
| TG-010 | P2 | completed | Define and implement a real SMB1/CIFS interop policy. Real SMB1 peer interoperability is excluded from current release-gated interoperability claims; any future real SMB1 testing must be isolated, opt-in, and separate from default gates. | `docs/coverage-matrix.md`, `docs/interop-matrix.md`, `README.md`, `OPENCIFS.md`, and this file consistently state that SMB1 codec/bootstrap work exists but real SMB1 peer interop remains outside the current claim scope. | Completed in docs; add an `eng/` SMB1 harness only if the project deliberately expands scope later. |
| TG-011 | P2 | in_progress | Add Kerberos SMB interoperability coverage after native Kerberos support exists. The codebase now has explicit client and server authentication-mechanism plumbing plus bounded Kerberos SPNEGO advertisement/selection handling, but it still lacks real Kerberos token exchange and SMB session-key derivation. Test domain-backed authentication against Windows and, if feasible, Samba AD after that product work lands. | Coverage rows move from Kerberos backlog to implemented or shared as appropriate; interop evidence records domain setup, principal, dialect, signing, encryption, and failure modes without storing secrets. | Groundwork now exists in `src/OpenCIFS.Security/OpenCifsAuthenticationMechanism*.cs`, `src/OpenCIFS.Client/OpenCifsClientCredential.cs`, `src/OpenCIFS.Client/OpenCifsClientSession.cs`, `src/OpenCIFS.Server/OpenCifsServerOptions.cs`, and `src/OpenCIFS.Server/OpenCifsServerHost.cs`. Remaining blockers are still product-level: no GSS-API/SSPI-backed Kerberos token generation or verification, no exported Kerberos SMB session-key plumbing for signing or encryption, and no domain-backed external harness yet. |
| TG-012 | P2 | completed | Keep evidence freshness enforceable. The current policy is exact `AsOfDate` matching for passed interop rows and non-`n/a` coverage verification dates during release validation. | `eng/validate-release-artifacts.ps1` rejects stale passed matrix rows relative to its `-AsOfDate` value; evidence refreshes must update `docs/interop-matrix.md` and `docs/coverage-matrix.md` in the same change as the artifacts. | Completed in `eng/validate-release-artifacts.ps1` and documented in this register. |

Suggested execution order:
1. Run `eng/run-local-windows-server-interop.ps1` from an elevated PowerShell session, or point `eng/run-windows-server-interop.ps1` at another live Windows SMB target, so TG-001 can move from harness-ready to evidenced.
2. Finish TG-003 runner provisioning so the refreshed 2026-05-15 evidence stops depending on manual reruns.
3. Treat TG-011 as blocked on product work rather than test-harness work until real Kerberos token flow and SMB session-key plumbing exist.

## Conclusion

The repository is not yet at full interoperability testing.

What it has today:
- Strong unit, shared, loopback, and managed direct-TCP regression coverage.
- Refreshed 2026-05-15 bounded external interoperability against Samba in Docker, now with Bookworm and Trixie peer-matrix evidence plus Dockerized Samba DFS namespace coverage.
- Refreshed 2026-05-15 bounded external server coverage against Windows built-in SMB client and Linux kernel CIFS on SMB 2.1 and SMB 3.0.2, with an explicit `smb2002` host-policy skip recorded for the current WSL2/Docker Desktop kernel.
- Refreshed 2026-05-15 same-build managed two-process and bounded local package-feed cross-version interoperability evidence.

What is still missing for a full interop claim:
- `OpenCIFS.Client -> Windows server` passing evidence; the harness is now present for both pre-provisioned targets and elevated local-share provisioning, but this session was not elevated.
- Broader implementation diversity beyond the current Samba/Linux plus Windows/Python bounded lanes.
- Always-on CI execution of the external interop stack.
- Release-gated SMB 3.1.1 evidence, if the project wants it in scope.
- External durable-handle v2 pass evidence, broader SMB 3.x, Kerberos, and real SMB1 interoperability coverage.
- Published-release managed client/server cross-version compatibility evidence.
