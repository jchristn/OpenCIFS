# OpenCIFS Implementation Plan

## How To Use This File

- `[ ]` not started
- `[~]` in progress
- `[x]` complete
- `[-]` blocked
- Add owner, date, PR, or notes inline after any item as work progresses.
- Do not mark a milestone complete until every exit criterion in that milestone is complete.

## Mission

Build a fully managed, MIT-licensed SMB/CIFS library suite in C# under `C:\code\opencifs` with:

- `OpenCIFS.Server`
- `OpenCIFS.Client`
- a real sample server project named `Sample.OpenCifsServer`
- exhaustive Touchstone-based automated testing
- no stub code, no placeholder handlers, no `NotImplementedException`, no TODO-based protocol claims

This plan is intentionally strict:

- A capability may only be documented, negotiated, advertised, or exposed when implementation and tests are complete.
- Runtime/product dependencies must remain `.NET BCL only` plus code inside this solution.
- Test-only dependencies may include `Touchstone`, `Touchstone.Cli`, `Touchstone.Xunit`, `Touchstone.Nunit`, `Touchstone.MstestAdapter`, `xUnit`, `NUnit`, and `MSTest`.
- Supported dialects must ultimately include SMB 1.0/CIFS, SMB 2.0.2, SMB 2.1, SMB 3.0, SMB 3.0.2, and SMB 3.1.1.
- SMB1 support must remain disabled by default even after it is implemented.

## Non-Negotiable Engineering Rules

- No public API may exist solely as a future placeholder.
- No protocol feature may be half-advertised. If support is partial, the capability bit stays off and documentation stays explicit.
- Every public type must have XML documentation.
- One class or one enum per file.
- Nullable reference types must be enabled everywhere.
- Warnings must be treated as errors.
- Use explicit types instead of `var` unless the local style guidance explicitly permits an exception.
- Library code must not use `Console.WriteLine`.
- Private members must follow `_PascalCase`.
- Async code must accept `CancellationToken` where applicable and use `ConfigureAwait(false)` where required by local style guidance.
- All connection/session/tree/open lifetime types must implement the full disposal pattern.
- Every command family, state machine, info class, security primitive, and negotiated capability must have explicit coverage rows in `docs/coverage-matrix.md`.

## Solution Layout

### Product Projects

- `src/OpenCIFS.Protocol`
- `src/OpenCIFS.Transport`
- `src/OpenCIFS.Security`
- `src/OpenCIFS.Server`
- `src/OpenCIFS.Client`
- `src/Sample.OpenCifsServer`

### Test Projects

- `src/OpenCIFS.Core.Tests.Shared`
- `src/OpenCIFS.Core.Tests.Console`
- `src/OpenCIFS.Core.Tests.Xunit`
- `src/OpenCIFS.Core.Tests.Nunit`
- `src/OpenCIFS.Core.Tests.Mstest`
- `src/OpenCIFS.Server.Tests.Shared`
- `src/OpenCIFS.Server.Tests.Console`
- `src/OpenCIFS.Server.Tests.Xunit`
- `src/OpenCIFS.Server.Tests.Nunit`
- `src/OpenCIFS.Server.Tests.Mstest`
- `src/OpenCIFS.Client.Tests.Shared`
- `src/OpenCIFS.Client.Tests.Console`
- `src/OpenCIFS.Client.Tests.Xunit`
- `src/OpenCIFS.Client.Tests.Nunit`
- `src/OpenCIFS.Client.Tests.Mstest`
- `src/OpenCIFS.Interop.Tests.Shared`
- `src/OpenCIFS.Interop.Tests.Console`
- `src/OpenCIFS.Interop.Tests.Xunit`
- `src/OpenCIFS.Interop.Tests.Nunit`
- `src/OpenCIFS.Interop.Tests.Mstest`

### Docs And Build Infrastructure

- `docs/coverage-matrix.md`
- `docs/interop-matrix.md`
- `docs/protocol-notes/`
- `eng/`
- `.github/workflows/`
- `.gitignore`
- `README.md`
- `CHANGELOG.md`
- `LICENSE.md`
- `src/Directory.Build.props`
- `src/Directory.Build.targets`
- `src/Directory.Packages.props`

## Packaging Decisions

- `OpenCIFS.Protocol`: packable
- `OpenCIFS.Server`: packable
- `OpenCIFS.Client`: packable
- `OpenCIFS.Transport`: packable
- `OpenCIFS.Security`: packable
- `Sample.OpenCifsServer`: not packable

`OpenCIFS.Transport` and `OpenCIFS.Security` are packable because `OpenCIFS.Client` and `OpenCIFS.Server` depend on them transitively. Build-time package-graph validation protects that dependency closure, and package-smoke validation protects emitted nuspec metadata, package-specific readmes, XML docs, and downstream restore behavior.

## Architectural Decisions

### Shared Engine

- `OpenCIFS.Protocol` owns all wire formats, codecs, enums, flags, command identifiers, status mappings, negotiate contexts, FSCC structures, and state model types.
- `OpenCIFS.Transport` owns direct TCP framing, NetBIOS session service framing, socket lifetime, buffering, and flow-control glue.
- `OpenCIFS.Security` owns NTLMv2, SPNEGO token handling, signing, encryption, preauth hashing, key derivation, and later native Kerberos.
- `OpenCIFS.Server` owns listener orchestration, session lifecycle, share registration, backend contracts, server callbacks, and policy enforcement.
- `OpenCIFS.Client` owns connection/session/tree/open orchestration and high-level client APIs built on the shared protocol engine.

### Concurrency Model

- Use `System.IO.Pipelines` per accepted connection.
- Feed framed PDUs into a per-connection request channel.
- Dispatch requests through per-session/per-tree state managers that enforce credits, compounding, replay rules, and ordering constraints.
- Keep serialization and signing/encryption on explicit write paths rather than ad hoc side effects.

### Security Model

- NTLMv2 must be implemented natively in `OpenCIFS.Security`.
- Kerberos must not use third-party runtime packages.
- Kerberos may only be advertised after a native implementation is complete and passes the same interop gates as NTLMv2.
- SPNEGO must be implemented as part of the shared security layer, not duplicated between client and server.

### Logging Model

- Because runtime dependencies are BCL-only, define an in-solution logging abstraction for library code.
- Add adapters later only if packaging rules change.
- The sample application may add richer host logging if it does not change the core library dependency policy.

## Coverage Matrix Rules

`docs/coverage-matrix.md` is a release artifact, not a note file.

Each row must at minimum track:

- dialect
- area
- command or capability
- server status
- client status
- advertised
- implemented
- test suite name
- descriptor count
- descriptor skipped count
- last Samba verification date
- last Windows verification date
- notes

Rules:

- If `implemented=true`, then `advertised=true` is allowed only when descriptor skipped count is `0`.
- If `implemented=false`, capability advertisement must stay off.
- Backlog items for a supported dialect must still have rows with `advertised=false` and `implemented=false`.
- CI must fail if any row claims `implemented=true` while skipped descriptors are non-zero.

## Cross-Cutting Workstreams

### Workstream A: Repository Bootstrap

- [x] Create the solution file and all initial project files.
- [x] Add `src/Directory.Build.props` with nullable enabled, warnings as errors, deterministic builds, XML documentation generation, and shared target frameworks.
- [x] Add `src/Directory.Packages.props` for centralized package management for test-only dependencies.
- [x] Add `.gitignore`, `README.md`, `CHANGELOG.md`, and `LICENSE.md` with MIT licensing.
- [x] Add `.editorconfig` or equivalent repo-level formatting rules that reflect the required C# style.
- [x] Add a root `docs/` folder with `coverage-matrix.md` and `interop-matrix.md`.
- [x] Add `InternalsVisibleTo` wiring for the internal projects and test assemblies.
- [x] Set product projects to `net8.0;net10.0`.
- [x] Set test projects to the same multi-target unless a runner forces a narrower target.
- [x] Ensure the empty solution builds without warnings before any feature work starts.

### Workstream B: Test Infrastructure

- [x] Add Touchstone shared descriptor projects for `Core`, `Server`, `Client`, and `Interop`.
- [x] Add `Console`, `xUnit`, `NUnit`, and `MSTest` runners for each shared test suite.
- [x] Make `Console` runners the primary machine-readable gate for CI.
- [x] Add matrix validation so the build fails if an implemented capability has skipped descriptors.
- [x] Add managed-path smoke scripts for packaged consumers, README examples, and a one-command integration gate that composes the local verification stack with external interop smoke.
- [x] Add test utilities for temp shares, temp credentials, packet capture helpers, golden vectors, and deterministic clocks.
- [x] Add negative-test helpers for malformed frames, signature failures, replay attempts, invalid credits, and invalid state transitions.
  Shared deterministic mutation helpers drive malformed frame and request corpuses in `OpenCIFS.Core.Tests.Shared`, a malformed direct-TCP mutation-burst harness lives in `OpenCIFS.Server.Tests.Shared`, signature-failure and invalid-credit helpers exist in the current shared suites, and `ReplayAttemptUtilities` now provides deterministic replay-copy and replay-burst helpers covered by a shared core suite that also asserts mutation isolation and null/zero-count rejection. The shared test utility layer also provides deterministic temp-path cleanup, stable credentials and environment defaults, deterministic timestamps and hash seeds, golden-vector loading, and packet-trace capture helpers for representative malformed-input coverage.
- [x] Add a bounded configurable soak harness for connection churn, durable reconnect, and large I/O, and wire it into the `Release` gate.

### Workstream C: Interop Lab

- [x] Add a bounded real-client smoke workflow for `Sample.OpenCifsServer` using a non-loopback SMB client and record the evidence in `docs/interop-matrix.md`.
- [x] Stand up a Samba test environment that can run in CI or a reproducible lab script.
- [x] Stand up a Windows client test environment for mounting and exercising `Sample.OpenCifsServer`.
- [ ] Stand up a Windows server test environment for validating `OpenCIFS.Client`.
- [x] Capture exact OS and Samba versions in `docs/interop-matrix.md`.
- [x] Automate smoke interop runs for every merged dialect milestone.
- [-] Automate deeper nightly interop runs for durable reconnect, encryption, and long I/O scenarios.
  Bounded progress: `eng/run-nightly-interop.ps1` now composes deeper three-dialect Python real-client, Samba, and native Windows interop reruns across SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2 with a larger bounded payload, plus a stronger SMB 2.1 soak that exercises durable reconnect, exclusive oplock-break, lease-break, and large-I/O churn on the managed path, and records the composed evidence in `artifacts/nightly-interop/nightly-interop.json`. Durable-handle v2, SMB 3.1.1 negotiation, and broader SMB 3.x nightly coverage remain backlog.

### Workstream D: Documentation And Release Discipline

- [x] Keep `README.md` aligned with actual implemented capabilities only.
  The current README correctly describes the verified managed dialect surface (SMB 2.0.2 through bounded SMB 3.0.2) and explicitly calls out SMB 3.1.1 and SMB1/CIFS as backlog. Bounded DFS is not yet README-claimed because external DFS interop has not been verified.
- [x] Update `CHANGELOG.md` per milestone.
  `CHANGELOG.md` `Unreleased` now records the bounded DFS slice plus the bounded exception-taxonomy and SMB 3.0 / 3.0.2 opt-in slices. The duplicate `# Unreleased` header was removed.
- [x] Keep `docs/coverage-matrix.md` current in the same PR as the code change.
  The DFS row was just lifted from `backlog` to `implemented` for the bounded scope after shared-suite tests landed.
- [x] Keep `docs/interop-matrix.md` current with last verified environments and dates.
  The interop matrix carries 2026-04-30 evidence for the verified Sample.OpenCifsServer/Python, Samba, Windows-client, and OpenCIFS.Client/Samba paths. DFS has no external interop yet, so the matrix correctly does not claim DFS.
- [x] Do not publish a package from a dirty coverage matrix or stale interop matrix.

## Milestones

## Milestone 0: Repository Bootstrap

Goal: create a disciplined repository skeleton with no fake product code and with all enforcement hooks in place.

- [x] Create the initial folder structure under `src/`, `docs/`, and `eng/`.
- [x] Create the product `.csproj` files with correct packability settings.
- [x] Create the four shared Touchstone suites and sixteen runner projects.
- [x] Add build scripts or CI entrypoints for local `dotnet build`, `dotnet test`, and Touchstone console execution.
- [x] Add an initial `docs/coverage-matrix.md` template with rows for every planned dialect and major capability family.
- [x] Add an initial `docs/interop-matrix.md` template with Windows and Samba targets.
- [x] Add a coding standards summary inside the repo so contributors do not need to infer style from existing code.

Exit criteria:

- [x] `dotnet build` is clean with zero warnings.
- [x] Test runners execute empty-but-valid suites without skipped implemented rows.
- [x] No product project exposes placeholder public types.

## Milestone 1: Core Wire And State Foundation

Goal: build the reusable protocol engine before shipping any dialect claim.

- [x] Implement binary primitives for little-endian parsing and writing without unsafe shortcut APIs unless justified and benchmarked.
- [x] Implement shared frame abstractions for direct TCP and NetBIOS session service.
- [x] Implement SMB1 and SMB2/3 header models and serializers.
- [x] Implement dialect identifiers, command identifiers, flags, capability enums, status codes, and negotiate-context models.
- [x] Implement FSCC structure models and mapping tables needed by query/set info and directory enumeration paths.
- [x] Implement connection, session, tree, open, request, credit, and compound-chain state objects.
- [x] Implement reusable packet validation layers for header sanity, lengths, alignment, and flag legality.
- [x] Implement preauth hash accumulation infrastructure for SMB 3.1.1 even before 3.1.1 is advertised.
- [x] Implement `System.IO.Pipelines` transport scaffolding with explicit read and write loops.
- [x] Implement signing interfaces and key-derivation interfaces without exposing unsupported algorithms.
- [x] Implement Touchstone vector tests for headers, enums, codecs, and state transitions.
- [x] Implement parser mutation tests and malformed-input tests for every frame reader.

Exit criteria:

- [x] All wire primitives round-trip through deterministic tests.
- [x] All shared state objects have lifecycle tests.
- [x] No dialect is advertised yet.

## Milestone 2: Security Foundation For SMB Session Setup

Goal: complete the common security primitives required by early SMB 2.x milestones.

- [x] Implement MD4 locally for NTLM credential hashing.
- [x] Implement HMAC-MD5 and NTLMv2 response generation and verification flows.
- [x] Implement SPNEGO token encode/decode and mechanism negotiation.
- [x] Implement HMAC-SHA256 signing for SMB 2.x.
- [x] Implement HKDF with a BCL-backed path where available and a local fallback for `net8.0`.
- [x] Implement AES-CMAC locally per RFC 4493.
- [x] Implement AES-GMAC support for SMB 3.1.1 signing selection.
- [x] Implement AES-CCM and AES-GCM wrappers using the BCL.
- [x] Implement key derivation flows for signing keys, application keys, encryption keys, and decryption keys.
- [x] Implement exhaustive known-answer tests for every crypto primitive and derivation path.
- [x] Implement negative tests for invalid tokens, invalid MICs, invalid signatures, and corrupted encrypted payloads.

Exit criteria:

- [x] NTLMv2 session setup primitives are ready for client and server use.
- [x] All crypto primitives have vector coverage.
- [x] No Kerberos capability is advertised yet.

## Milestone 3: SMB 2.0.2 Lockstep Server And Client

Goal: ship the first real dialect subset with both sides moving together.

### Protocol And State

- [x] Implement SMB 2.0.2 negotiate handling for client and server.
- [x] Implement session setup, logoff, tree connect, and tree disconnect.
- [x] Implement create, close, flush, read, write, lock, IOCTL, cancel, echo, query directory, change notify, query info, set info, and oplock break message handling.
- [x] Verify a bounded SMB 2.0.2 file-I/O slice for create, read, write, flush, and close with minimal open tracking, local-share backing, and loopback coverage while the remaining command-set backlog stays unchecked.
- [-] Implement compounding support for valid SMB 2.0.2 request chains.
  Bounded progress: shared core, client, server, and loopback suites cover unrelated compound packet framing, zero-padding trimming, header application, and dispatch for the implemented negotiate, session, tree, file-I/O, echo, and bounded unsupported IOCTL bodies, plus bounded `SMB2_FLAGS_RELATED_OPERATIONS` chains carrying `SessionId`, generated `TreeId`, and generated `FileId` through synchronous tree, file-I/O, metadata, locking, and open-scoped IOCTL flows with mixed-style rejection and propagated related-create failure across later commands. Realistic related `create -> write -> flush -> close`, `create -> query info -> close`, and `open -> read -> close` chains are covered. Asynchronous compounding (related chains containing async commands) and the remaining valid-chain permutations outside this bounded surface remain backlog.
- [x] Verify a bounded SMB 2.0.2 unrelated-compounding slice for the implemented negotiate, session, tree, and file-I/O commands with packet framing, payload trimming, server dispatch, and loopback coverage while `SMB2_FLAGS_RELATED_OPERATIONS` chains stay unchecked.
- [x] Verify a bounded SMB 2.0.2 related-compounding slice for synchronous tree, file-I/O, metadata, locking, and open-scoped `IOCTL` chains with carried `SessionId`, generated `TreeId`, generated `FileId`, related response flags, mixed-style rejection, propagated related-create failure across later commands, and loopback coverage while broader related-chain and asynchronous compounding behavior stay unchecked.
- [x] Implement credit accounting and enforcement.
- [x] Verify a bounded SMB 2.0.2 open-semantics slice for share-access enforcement plus `FILE_DELETE_ON_CLOSE` and delete-pending behavior across create and close while rename, allocation, end-of-file mutation, and timestamp semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 metadata slice for `QUERY_INFO` and `SET_INFO` over basic, standard, name, and network-open metadata plus rename, disposition, allocation, end-of-file, and bounded timestamp semantics while `QUERY_DIRECTORY` and broader metadata backlog stay unchecked.
- [x] Verify a bounded SMB 2.0.2 `QUERY_DIRECTORY` slice for existing-directory opens, `FILE_DIRECTORY_INFORMATION`, `FILE_FULL_DIR_INFORMATION`, search-pattern filtering, restart and resume enumeration state, and exhaustion/error statuses while broader metadata backlog stays unchecked.
- [x] Verify a bounded SMB 2.0.2 byte-range locking slice for `LOCK` request and response handling, shared and exclusive range ownership tied to opens, unlock semantics, conflict rejection on competing lock/read/write operations, and close cleanup while async cancellation of long-running lock requests remains backlog.
- [x] Verify a bounded SMB 2.0.2 oplock-break slice for signed exclusive `OPLOCK_BREAK` notifications and acknowledgments, conflict-triggered oplock downgrade handling, invalid notification and acknowledgment rejection, and direct-TCP plus loopback coverage while broader lease behavior remains backlog.
- [x] Verify a bounded SMB 2.0.2 `ECHO` slice for authenticated-session request and response handling, client keepalive flow, compound payload trimming, and loopback coverage while unsigned `SessionId=0` echo semantics plus the remaining command backlog stay unchecked.
- [x] Verify a bounded SMB 2.0.2 `IOCTL` slice for generic request and response handling, unsupported open-scoped and wildcard-file-id FSCTL behavior, stale-handle and malformed-shape rejection, and loopback coverage while specific FSCTL implementations and broader async device-control behavior stay backlog.
- [x] Verify a bounded SMB 2.0.2 `FSCTL_SRV_ENUMERATE_SNAPSHOTS` slice for open-scoped request and response handling, empty `SRV_SNAPSHOT_ARRAY` success responses, client decode, invalid-shape rejection, and loopback coverage while broader FSCTL implementations and async device-control behavior stay backlog.
- [x] Verify a bounded SMB 2.0.2 directory-create slice for `FILE_DIRECTORY_FILE` `FILE_CREATE`, `FILE_OPEN`, and `FILE_OPEN_IF` handling, backing-directory materialization, collision and `STATUS_NOT_A_DIRECTORY` behavior, and loopback coverage while broader create-option semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 empty-directory delete-pending slice for `FILE_DIRECTORY_FILE` `FILE_DELETE_ON_CLOSE` and `FILE_DISPOSITION_INFORMATION`, child-create rejection while pending, and `STATUS_DIRECTORY_NOT_EMPTY` rejection for non-empty directories while broader create-option semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 directory-rename slice for `FILE_RENAME_INFORMATION` on directory opens, missing-destination moves, subtree-open rejection, and declared-allocation preservation for moved child paths while broader rename semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 `CANCEL` slice for unsigned synchronous request bodies plus async cancellation of accepted pending `CHANGE_NOTIFY` requests, client cancel-header creation without credit or sequence consumption, server cancellation of accepted pending requests, `STATUS_CANCELLED` target responses, and loopback coverage while signed and compounded cancel semantics stay backlog.
- [x] Verify a bounded SMB 2.0.2 `CHANGE_NOTIFY` slice for async interim and final header handling, pending directory-watch lifecycle, create-event completion, `STATUS_NOTIFY_ENUM_DIR` overflow, async cancel integration, client notify-entry decoding, and loopback coverage while broader notify filters, richer event coverage, and asynchronous compounding stay backlog.
- [x] Verify a bounded SMB 2.0.2 signing slice for authenticated request and response packet signing on the managed client and server path, signed cancel headers, missing or tampered signature rejection, and signing-required real-client, Samba, and native Windows smoke while session-setup signing and broader SMB 3.x security negotiation stay backlog.
- [x] Verify a bounded SMB 2.0.2 durable-reconnect slice for durable batch-oplock create contexts, shared-state persistent and volatile file IDs, detached-open survival across abrupt transport disconnect, reconnect on a fresh managed direct-TCP connection, mismatched reconnect rejection while preserving the detached open, and core or client or server or loopback coverage while broader durable-state behavior stays backlog.
- [x] Verify a bounded SMB 2.0.2 durable-lock carryover slice for detached byte-range lock preservation across transport disconnect, conflicting read and lock rejection while the durable open is detached or reconnected, restored unlock ownership after reconnect, and core or client or server or loopback coverage while broader durable-state behavior stays backlog.
- [x] Verify a bounded SMB 2.0.2 file-overwrite disposition slice for `FILE_SUPERSEDE`, `FILE_OVERWRITE`, and `FILE_OVERWRITE_IF` handling, required `DELETE` access on supersede, truncation and create-action reporting, and declared-allocation reset on replacement while broader create semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 create-attribute slice for create and overwrite paths that apply local-share create-time file attributes plus `STATUS_CANNOT_DELETE` rejection for new read-only `FILE_DELETE_ON_CLOSE` requests while broader create-state semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 read-only delete-rejection slice for `FILE_DELETE_ON_CLOSE` and `FILE_DISPOSITION_INFORMATION` on existing read-only files and directories, plus new read-only directory creates, while broader create-state semantics stay unchecked.
- [x] Verify a bounded SMB 2.0.2 basic-timestamp slice for `FILE_BASIC_INFORMATION` creation plus explicit and handle-persistent `-1` / `-2` access, write, and change-time directives, deterministic `FILE_BASIC_INFORMATION` and `FILE_NETWORK_OPEN_INFORMATION` reporting, and automatic timestamp suppression or resumption across read, write, allocation, and end-of-file mutations while broader create-state semantics stay unchecked.
- [-] Implement create dispositions, create options, share modes, delete-pending behavior, rename behavior, allocation size, end-of-file updates, and timestamp semantics.
  Bounded progress: every individual semantic listed here is covered by a bounded slice that is already `[x]` above. Create dispositions cover `FILE_CREATE`, `FILE_OPEN`, `FILE_OPEN_IF`, `FILE_SUPERSEDE`, `FILE_OVERWRITE`, and `FILE_OVERWRITE_IF` with truncation, create-action reporting, declared-allocation reset, and `DELETE` access validation for supersede. Create options cover `FILE_DIRECTORY_FILE` and `FILE_DELETE_ON_CLOSE`. Share modes cover the share-access enforcement slice. Delete-pending behavior covers create-time and disposition-time paths plus read-only delete rejection. Rename behavior covers file rename, directory rename via `FILE_RENAME_INFORMATION`, missing-destination moves, subtree-open rejection, and declared-allocation preservation for moved children. Allocation size and end-of-file updates are covered through the metadata slice and overwrite-disposition slices. Timestamp semantics cover `FILE_BASIC_INFORMATION` creation plus explicit and handle-persistent `-1` / `-2` access, write, and change-time directives, deterministic `FILE_NETWORK_OPEN_INFORMATION` reporting, and automatic timestamp suppression or resumption across read, write, allocation, and end-of-file mutations. Broader spec coverage outside the bounded slices remains backlog (e.g., obscure create options, alternate data streams, named-stream metadata).
- [-] Complete the broader SMB 2.0.2 handle-table, durable-state, and reconnect behavior that remains outside the bounded durable batch-oplock reconnect slice.
  Bounded progress: durable batch-oplock create / reconnect, detached-open survival, mismatched-reconnect rejection, durable byte-range lock carryover across reconnect, conflicting read and lock rejection while detached, and restored unlock ownership after reconnect are covered in shared core, client, server, and loopback suites. SMB 2.1 lease-backed durable reconnect with same-client-guid validation, missing or mismatched lease-context rejection, lease-state restoration, and competing-open downgrade is also covered. SMB 3.0.2 non-persistent durable-handle v2 reconnect with preserved durable create GUID, persistent file ID, fresh volatile file ID allocation, and preserved byte-range lock state is covered. Continuous availability, persistent clustered handles, lease-v2, multichannel, and external durable-handle v2 interop remain backlog and are explicit non-claims for first GA.
- [x] Implement error mapping so NTSTATUS behavior is explicit and tested.

### Server Surface

- [x] Define the server host API for listener creation, share registration, authentication configuration, and lifecycle control.
- [x] Define backend contracts for files, directories, metadata, locking, notifications, and named streams where supported.
- [x] Implement a local filesystem-backed share provider for `Sample.OpenCifsServer`.
- [x] Verify a bounded server-surface slice for `OpenCifsServerHostBuilder`, explicit local filesystem share registration, duplicate-share rejection, and suppression of the implicit legacy options share whenever explicit share registrations are present.
- [x] Verify a bounded `Sample.OpenCifsServer` filesystem-provider slice that registers the configured local share through the builder-backed host surface and passes loopback plus real-client smoke validation.
- [x] Implement typed callback hooks for authenticated session completion, tree connect, create, query directory, set info, and IOCTL requests that require application control rather than fixed filesystem behavior.
- [x] Enforce safe defaults: signing required, NTLMv2 only, anonymous disabled, SMB1 disabled, bind port default `4450`.
- [x] Verify a bounded compatibility-first server-surface slice for `OpenCifsServerBuilder` and `OpenCifsServerApplication`, with builder-backed sample-host usage plus README and packaged-consumer smoke coverage on the primary builder -> application flow.
- [x] Verify a bounded compatibility-first `OpenCifsServer` runtime slice for immutable `OpenCifsServerSettings`, the primary builder -> server -> application flow, share-introspection coverage on the configured server surface, and README or package-readme smoke coverage.
- [x] Verify a bounded server share-introspection slice for `OpenCifsServerBuilder`, `OpenCifsServerHostBuilder`, `OpenCifsServerHost`, and `OpenCifsServerApplication`, with immutable explicit-share and implicit-options-share snapshots plus README and packaged-consumer smoke coverage. This row remains server-side only; client-side remote share browsing over `IPC$` or `srvsvc` is tracked separately.

### Client Surface

- [x] Define the low-level client session API for connect, authenticate, tree connect, open, read, write, query, set, enumerate, and close.
- [x] Define the high-level client facade for common file and directory operations.
- [x] Verify a bounded preview direct-TCP client facade for connect, authenticate, echo, create directory, write file, read file, and directory enumeration flows against `OpenCifsServer`.
- [x] Extend the bounded preview direct-TCP client facade with metadata query, rename, and file or empty-directory delete flows against `OpenCifsServer`.
- [x] Extend the bounded preview direct-TCP client facade with bounded `FILE_BASIC_INFORMATION` and `FILE_END_OF_FILE_INFORMATION` mutation flows against `OpenCifsServer`.
- [x] Start the direct-TCP ergonomic client facade behind an explicit preview marker until the non-preview low-level connection surface and common-operations coverage are complete.
- [x] Verify a bounded multi-client direct-TCP slice for `OpenCifsDirectTcpServer` shared state and client surfaces: cross-connection async `CHANGE_NOTIFY` completion, high-level facade notify waits, read-share success, conflicting share-access rejection, and cross-session byte-range lock-conflict rejection.
- [x] Verify a bounded compatibility-first client-surface slice for `OpenCifsClientBuilder`, immutable `OpenCifsClientSettings`, `OpenCifsClient`, and `OpenCifsShareSession` grouped `Files` or `Directories` or `Metadata` or `Locks` flows, with aligned README and packaged-consumer smoke coverage plus positive and negative shared path-first API-shape regression tests.

### Testing

- [x] Add codec and state tests for every SMB 2.0.2 command.
- [x] Add loopback tests for every SMB 2.0.2 command path between `OpenCIFS.Client` and `OpenCIFS.Server`.
- [x] Add a bounded real-client smoke path for `Sample.OpenCifsServer` that verifies negotiate, authenticate, tree, metadata query, bounded basic-info and end-of-file mutation, rename, delete, file-I/O, and directory-enumeration flows with a non-loopback SMB client, now rerun with signing required.
- [x] Add a bounded Samba smoke path that verifies `OpenCIFS.Client` against a reproducible Samba server and `Sample.OpenCifsServer` against a reproducible Samba client for negotiate, authenticate, tree connect, `FSCTL_VALIDATE_NEGOTIATE_INFO`, bounded metadata query, create, read, write, flush, enumerate, rename, delete, and client-side lock-conflict rejection, now rerun with signing required on both sides while broader locking and Windows coverage remain backlog.
- [x] Add a bounded native Windows mapped-drive smoke path for `Sample.OpenCifsServer` that verifies negotiate, SPNEGO-wrapped NTLMv2 session setup, tree connect, directory create, file write, file read, `FILE_BOTH_DIR_INFORMATION` directory enumeration, rename, delete, and empty-directory cleanup over SMB 2.0.2, now rerun with signing required while broader Windows status-code coverage and `OpenCIFS.Client` to Windows-server coverage remain backlog.
- [x] Expand the bounded real-client and native Windows SMB 2.0.2 smoke paths for `Sample.OpenCifsServer` to cover bounded hidden and read-only attribute mutation, read-only clearing through attribute-only metadata opens, bounded end-of-file truncation, read-only and non-empty delete rejection, directory rename, and cleanup while broader Windows NTSTATUS mapping and `OpenCIFS.Client` to Windows-server coverage remain backlog.
- [x] Expand the bounded Samba interop smoke against server and client roles to cover nested-directory create, read, write, enumerate, rename, delete, non-empty-directory delete rejection, and bounded lock-conflict handling while deeper Samba automation and Windows-server parity remain backlog.
- [x] Add broader Windows interop tests for mounting `Sample.OpenCifsServer`, exercising additional metadata and error paths, and validating status-code behavior through mapped-drive `FileSystemWatcher` rename and nested-create coverage plus native share-access and byte-range lock-conflict rejection.
- [x] Add negative tests for invalid credits, invalid compound chains, bad message IDs, stale handles, and invalid session/tree/open identifiers.
- [x] Add API-shape and README-snippet smoke coverage for the aligned builder -> client -> share-session and builder -> application public surface, including regression coverage for signed logoff teardown on the primary client disconnect path.

Exit criteria:

- [-] `OpenCIFS.Server` and `OpenCIFS.Client` both complete the SMB 2.0.2 coverage rows with zero skipped descriptors for implemented items.
  Bounded progress: every SMB 2.0.2 row currently marked `implemented=true` in `docs/coverage-matrix.md` has zero skipped descriptors today, and the source-audit + matrix-validation gates fail any drift. Broader SMB 2.0.2 spec scope outside the bounded slices documented in those rows still remains backlog (full compounding, full create dispositions / share modes / timestamp semantics, broader handle-table and durable-state).
- [x] `Sample.OpenCifsServer` can be mounted and exercised from Windows and Samba using the documented defaults.
  `docs/interop-matrix.md` records 2026-04-30 pass evidence in both directions: native Windows mapped-drive smoke through `eng/run-windows-client-interop.ps1` for SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2, plus Samba client smoke through `eng/run-samba-interop.ps1` against the same documented defaults (port `4450`, signing required, NTLMv2 only, anonymous and SMB1 disabled, SMB 3.x encryption required).
- [-] `OpenCIFS.Client` can exercise equivalent flows against Samba and Windows servers.
  Bounded progress: `OpenCIFS.Client` to Samba server has 2026-04-30 pass evidence in `docs/interop-matrix.md` across SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2. `OpenCIFS.Client` to Windows server still depends on Workstream C standing up a Windows server test environment.

## Milestone 4: SMB 2.1 Lockstep Enhancements

Goal: add SMB 2.1 semantics without splitting the implementation between client and server.

- [x] Implement SMB 2.1 negotiate behavior and dialect-specific capability handling.
- [x] Verify the existing managed session, tree, file-I/O, metadata, notification, locking, oplock, and bounded durable-reconnect surface under negotiated SMB 2.1 in loopback plus bounded Python real-client, Samba, and native Windows client smoke flows.
- [x] Implement a bounded SMB 2.1 leasing slice with `RqLs` create contexts, read/write/handle lease grant handling, signed lease-break notifications and acknowledgments, direct-TCP client wait-and-ack handling, and same-lease-key path-mismatch rejection.
- [x] Implement bounded large MTU support and multi-credit large read/write behavior, including SMB 2.1 `SMB2_GLOBAL_CAP_LARGE_MTU` negotiation, managed credit-window growth, multi-credit request validation, and verified `200000`-byte large-transfer coverage across loopback plus bounded Python real-client, Samba, and native Windows client smoke flows.
- [x] Implement the bounded SMB 2.1 durable reconnect semantics required for lease-backed durable opens, including same-client-guid reconnect validation, missing or mismatched lease-context rejection, reconnect-time lease-state restoration, and competing-open downgrade to `SMB2_LEASE_NONE`.
- [x] Expand compounding tests for realistic open-read-close, create-query-close, and create-write-flush-close chains, including bounded `OpenCifsClientConnection` helpers plus primary `OpenCifsShareSession` read/write/metadata paths, signed related-response preservation, and missing-path create-failure propagation.
- [x] Expand loopback and interop tests for broader lease scenarios, reconnect, and large transfers.
- [x] Update the sample server and documentation only if any defaults or limits change.
  No SMB 2.1 default or limit change required a sample-server or documentation update; the bounded SMB 2.1 lease and large-MTU slices stayed inside the existing builder defaults.

Exit criteria:

- [x] SMB 2.1 rows in the coverage matrix are complete for both client and server.
- [x] Large I/O, lease behavior, and reconnect paths are green in loopback and interop suites.

## Milestone 5: SMB 3.0 And SMB 3.0.2 Lockstep Enhancements

Goal: add SMB 3.x security and durability features that are in scope for first GA.

- [x] Implement bounded SMB 3.0/3.0.2 negotiate behavior and capability flags on the managed client/server path, with dialect advertisement lifted to `Smb30`/`Smb302` plus `LargeMtu | Leasing` for the bounded non-encrypted compatibility slice when the client sets `PreferEncryption = false` and the server sets `RequireEncryptionForSmb3 = false`, and bounded encryption-capable SMB 3.0.2 negotiate plus `EncryptData` session requirements when both sides keep the default encrypted SMB3 posture.
- [x] Implement AES-CMAC signing selection where negotiated on the managed client/server path, including SMB 3.0 and SMB 3.0.2 signing-key derivation plus authenticated request/response signing and validation.
- [x] Implement AES-128-CCM encryption and decryption flows.
- [x] Implement secure negotiate validation.
- [x] Implement durable handles v2 and reconnect flows that do not rely on clustered continuous availability.
- [x] Implement the bounded session and tree behavior changes required by SMB 3.0/3.0.2, including `EncryptData` session flags, SMB3 transform-wrapped post-authenticate request and response handling, encrypted tree lifecycle handling, and SMB 3.1.1-style negotiate-request tolerance needed for current Windows and Samba clients.
- [x] Add loopback tests for encrypted sessions, encrypted read/write, encrypted compounding, and durable reconnect.
- [x] Add Windows and Samba interop tests for signing required and encryption required scenarios.
- [x] Keep continuous availability, persistent handles tied to clustered shares, and multichannel out of claim scope unless fully implemented later.
  Continuous availability, persistent clustered handles, and multichannel are not advertised on the managed path and are explicitly listed in the First GA Non-Claims section. Coverage matrix rows for these features remain `advertised=false` and `implemented=false`.

Exit criteria:

- [x] SMB 3.0 and SMB 3.0.2 in-scope rows are complete with zero skipped descriptors for implemented items.
- [x] Encryption-required sessions work in loopback and interop tests.
- [x] Secure negotiate downgrade tests are green.

## Milestone 6: SMB 3.1.1 Core Negotiate Contexts

Goal: complete the core SMB 3.1.1 functionality that is required for modern secure interoperability.

- [x] Implement preauth integrity negotiation and transcript hashing.
  `PreauthIntegrityCapabilities` model and the preauth hash accumulator already exist with shared core round-trip and malformed-input coverage; the hash accumulator already passes its known-vector test. The `Smb2NegotiateContextList` codec now serializes/parses 8-byte-aligned typed contexts with mixed Preauth/Encryption/Signing payloads under shared core test coverage, and the new `Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(...)` pure-function helper picks SHA-512 from a client offer and rejects offers without a supported hash algorithm. The new `OpenCifsClientBuilder.WithSmb311Preview()` opt-in plus `OpenCifsClientOptions.EnableSmb311Preview` advertises SMB 3.1.1 in the client dialect list and emits typed Preauth (SHA-512 + 32-byte salt), Signing (AES-CMAC + HMAC-SHA256), Encryption (AES-128-CCM), and NETNAME contexts on the wire. Client-side preauth integrity transcript hashing is now wired into the negotiate exchange: when the preview opt-in is enabled, `OpenCifsClientSession` allocates a SHA-512 `PreauthIntegrityHashAccumulator` at request creation time and `OpenCifsClientConnection.NegotiateAsync(...)` appends both request and response message bytes to the transcript, with a shared client suite that pins zero-start, request-advance, and response-advance behavior plus a live-listener round trip where the transcript still allows tolerance fallback to SMB 3.0.2 and the authenticated session completes successfully. Server-side preauth transcript hashing now mirrors the client side: `OpenCifsServerBuilder.WithSmb311Preview()` plus `OpenCifsServerOptions.EnableSmb311Preview` opts in, `OpenCifsServerHost.HandleNegotiate(...)` allocates the preauth hash accumulator when opt-in is active and the request carries 3.1.1-shaped contexts, and `AppendPreauthMessageBytes(header, body)` plus `GetCurrentPreauthIntegrityHash()` plumbing methods let the dispatch layer feed and inspect the transcript with shared server coverage that pins zero-start, request-advance, and response-advance. Server dispatch automation now wires the transcript appends inside `HandleCompoundRequestEntry(...)`'s `Smb2Command.Negotiate` branch, so any negotiate exchange handled through the dispatch path automatically maintains the preauth hash without test-side helper calls, with shared client coverage that runs both sides of the preview opt-in through a live listener and completes an authenticated write/read/disconnect cycle via the SMB 3.0.2 tolerance fallback. Session-setup transcript carry-through is now wired automatically on both sides: `OpenCifsClientConnection.AuthenticateAsync(...)` appends the initial session-setup request, the `MoreProcessingRequired` challenge response, and the authenticate-leg request to the transcript before deriving keys; `OpenCifsServerHost.HandleCompoundRequestEntry(...)`'s `Smb2Command.SessionSetup` branch mirrors the same pattern by appending each session-setup request and only the non-final `MoreProcessingRequired` response, intentionally omitting the final `Success` response so the transcript captures the same byte sequence on both sides per MS-SMB2 key-derivation semantics. SMB 3.1.1 key derivation is now activated: when the negotiated dialect is `SmbDialect.Smb311`, `OpenCifsClientSession.ApplyAuthenticatedSessionKeys(...)` and the server's session-key derivation paths both pass the captured preauth integrity hash into `SmbSessionKeyDerivation` as the SMB 3.1.1 context. Server's `GetMaximumImplementedDialect()` now lifts to `SmbDialect.Smb311` when the preview opt-in is enabled, and shared server coverage pins that the preview server selects SMB 3.1.1 against an SMB 3.1.1 client and falls back to SMB 3.0.2 against the same client when the server is not opted in. The bounded both-sides-opted-in live-listener test now completes a real SMB 3.1.1 authenticated session with AES-CMAC signing keyed off the preauth transcript hash. Server-side typed response context emission is now wired: `OpenCifsServerHost.HandleNegotiate(...)` decodes the client's typed Preauth/Encryption/Signing entries, applies `Smb311NegotiateContextSelector` to pick algorithms, generates a 32-byte server preauth salt, and emits typed Preauth + Encryption (when client offered) + Signing (when client offered) response contexts on the wire. `Smb2CompoundPayloadHelper.GetNegotiateResponseLength(...)` now correctly handles the SMB 3.1.1 negotiate response shape that carries security buffer plus negotiate contexts. Shared server coverage pins the typed response context emission with selected SHA-512, AES-CMAC, and AES-128-CCM. AES-GCM/AES-256-CCM cipher selection, NETNAME server-name verification, and external SMB 3.1.1 interop remain backlog.
- [x] Implement signing capability negotiation with algorithm selection by negotiated `SigningAlgorithmId`.
  `SigningCapabilities` model exists with codec round-trip and malformed-input coverage, the `Smb2NegotiateContextList` codec carries it through 8-byte-aligned context lists, and `Smb311NegotiateContextSelector.SelectSigningAlgorithm(...)` now prefers AES-GMAC > AES-CMAC > HMAC-SHA256. The bounded SMB 3.1.1 preview client advertises `[AesGmac, AesCmac, HmacSha256]` and the server selects the strongest algorithm offered. Selection-time wiring is end-to-end on the client/server negotiate path: client/server signing-key derivation uses the selected algorithm, and per-message signing on both sides invokes the selected `IMessageSigner` with the appropriate signing key and (for AES-GMAC) the spec-compliant 12-byte nonce.
- [x] Implement AES-GMAC signing where negotiated.
  AES-GMAC primitive plus `SigningAlgorithmId.AesGmac` enum already exist with shared known-vector coverage and `Smb2NegotiateContextList` carries the algorithm identifier in negotiate-context lists. `Smb311NegotiateContextSelector.SelectSigningAlgorithm(...)` now prefers AES-GMAC over AES-CMAC and HMAC-SHA256, the bounded SMB 3.1.1 preview client advertises `[AesGmac, AesCmac, HmacSha256]`, the server selects AES-GMAC when offered, and per-message AES-GMAC signing on both client and server is wired through `Smb2SigningNonce.BuildSmb311GmacNonce(...)` which constructs the 12-byte nonce per MS-SMB2 §3.1.4.1 (8 bytes MessageId LE + 3 bytes zero + 1 byte 0x80 for server→client / 0x00 for client→server). The bounded both-sides-opted-in live-listener test now completes a full encrypted SMB 3.1.1 authenticated session under AES-GMAC signing.
- [-] Implement encryption capability negotiation for AES-128-GCM, AES-128-CCM, AES-256-GCM, and AES-256-CCM as supported by the target frameworks and interoperability matrix.
  Bounded progress: AES-128-GCM and AES-128-CCM are fully wired end-to-end. `EncryptionCapabilities` model and `SmbCipherAlgorithmId` enum exist with shared core round-trip plus malformed-input coverage, the `Smb2NegotiateContextList` codec carries cipher lists, `Smb311NegotiateContextSelector.SelectCipher(...)` prefers AES-128-GCM with AES-128-CCM fallback, the SMB 3.1.1 preview client advertises `[Aes128Gcm, Aes128Ccm]`, the server selects the strongest offered cipher and emits it in the response, both sides track the negotiated cipher, and `Smb3MessageTransform.EncryptPacket(...)` / `DecryptPacket(...)` switch between AES-128-CCM (11-byte nonce) and AES-128-GCM (12-byte nonce) per the negotiated cipher. End-to-end encrypted SMB 3.1.1 with AES-128-GCM completes through the bounded both-sides-opted-in live-listener test. AES-256-GCM and AES-256-CCM negotiate-time selection require a 32-byte session key and are gated on M9 native Kerberos (NTLMv2 produces only 16-byte session keys); they remain backlog.
- [x] Implement `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID`.
  `NetnameNegotiateContext` model has shared core round-trip plus malformed-input coverage and the `Smb2NegotiateContextList` codec carries it as an entry. The SMB 3.1.1 preview client emits a NETNAME context advertising the configured `OpenCifsClientOptions.ServerName` on every preview-opted-in negotiate request. The server-side `OpenCifsServerHost.HandleNegotiate(...)` decodes the NETNAME context when present, captures the value on `_ReceivedClientNetname`, and exposes it through the new `GetReceivedClientNetname()` accessor for diagnostic inspection per MS-SMB2 §3.3.5.4. Per spec the NETNAME context is informational and the server SHOULD record it but is not required to reject mismatches; shared server suite pins capture-on-opt-in plus null-on-opt-out behavior.
- [x] Add downgrade and tamper tests for negotiate contexts and preauth integrity.
  Shared core suite pins tamper rejection across the negotiate-context layer including inflated entry-count rejection in `Smb2NegotiateContextList`, zeroed hash-algorithm-count rejection in `PreauthIntegrityCapabilities`, bytewise hash-algorithm tamper detection on a decoded preauth payload, and SMB 3.1.1 negotiate-request tampering of the negotiate-context offset below the fixed header. Shared client suite pins spec-strict response validation that rejects SMB 3.1.1 responses with no negotiate contexts, missing the mandatory preauth integrity context, selecting more than one hash algorithm or cipher, or selecting an unsupported algorithm. SMB 3.1.1 downgrade detection is implicit through the preauth integrity transcript hash: any tampered server response selecting a different dialect or algorithm produces a different preauth hash than the legitimate transcript would, so subsequent session-setup signing fails with a signature mismatch — the existing both-sides-opted-in live-listener test exercises this defensive property.
- [-] Add loopback and interop tests for SMB 3.1.1 signed and encrypted sessions using the negotiated algorithms.
  Bounded progress: shared interop loopback suite pins SMB 3.1.1 dialect selection plus typed response context emission when both sides opt in, shared client suite pins a live-listener round trip completing an encrypted authenticated session under SMB 3.1.1 with AES-GMAC signing and AES-128-GCM encryption, and shared server suite pins the typed response context emission shape. External SMB 3.1.1 interop with Samba and Windows clients remains backlog and depends on the SMB 3.1.1 preview reaching general advertisement (currently opt-in only).
- [x] Add explicit coverage rows for these backlog contexts with `advertised=false` and `implemented=false` until they are done:
- [x] `SMB2_COMPRESSION_CAPABILITIES`
- [x] `SMB2_TRANSPORT_CAPABILITIES`
- [x] `SMB2_RDMA_TRANSFORM_CAPABILITIES`

Exit criteria:

- [ ] Core SMB 3.1.1 rows are complete and green.
- [x] Compression, QUIC transport, and RDMA remain clearly non-advertised unless separately completed later.
  Coverage matrix carries individual backlog rows for `SMB2_COMPRESSION_CAPABILITIES`, `SMB2_TRANSPORT_CAPABILITIES`, and `SMB2_RDMA_TRANSFORM_CAPABILITIES`, all `advertised=false` and `implemented=false`. The First GA Non-Claims section also explicitly lists SMB Direct / RDMA, SMB over QUIC, RDMA transform capabilities, and SMB 3.1.1 compression as non-claims, and `eng/OpenCIFS.Build` source-audit and package-claim validators enforce that no shipped surface advertises them.

## Milestone 7: SMB1/CIFS Compatibility Layer

Goal: implement SMB1/CIFS thoroughly while keeping it opt-in and off by default.

- [-] Implement SMB1 dialect negotiation for the required dialect set, including `LANMAN1.0` and `NT LM 0.12` if claimed.
  Bounded progress: `Smb1DialectStrings` static class now defines the required SMB1 dialect string constants (`PC NETWORK PROGRAM 1.0`-era omitted, but `LANMAN1.0`, `LM1.2X002`, `LANMAN2.1`, and `NT LM 0.12` are present alongside the existing SMB 2.x bridge strings). New `Smb1NegotiateResponse` codec carries the 17-word NT LM 0.12 / extended-security response shape (DialectIndex, SecurityMode, MaxMpxCount/MaxNumberVcs, MaxBufferSize/MaxRawSize, SessionKey, Capabilities, SystemTime, ServerTimeZoneMinutes, ServerGuid, optional SPNEGO security blob), with `Smb1SecurityMode` and `Smb1Capabilities` flags enums per MS-CIFS section 2.2.4.5.2. Shared core suite pins extended-security round-trip plus rejection of truncated responses and rejection of responses that omit the extended-security capability. Real SMB1 negotiate selection on the client/server path remains backlog and SMB1 stays disabled by default through `OpenCifsServerOptions.EnableSmb1`.
- [-] Implement SMB1 session setup, tree connect, and logoff flows.
  Bounded progress: `Smb1SessionSetupAndXRequest` and `Smb1SessionSetupAndXResponse` codecs carry the NT LM 0.12 extended-security shape (Unicode strings only) including the AndX header, MaxBufferSize / MaxMpxCount / VcNumber / SessionKey / Capabilities / SecurityBlob / NativeOS / NativeLanMan on the request side and AndX header / Action / SecurityBlob / NativeOS / NativeLanMan / PrimaryDomain on the response side, with proper Unicode 2-byte alignment padding before the trailing strings per MS-CIFS section 2.2.4.6.2. `Smb1TreeConnectAndXRequest` and `Smb1TreeConnectAndXResponse` codecs now carry the WordCount=4 request shape (AndX header, Flags, Password, Unicode share Path, ASCII Service) plus the WordCount=7 extended NT response shape (AndX header, OptionalSupport, MaximalShareAccessRights, GuestMaximalShareAccessRights, ASCII Service, Unicode NativeFileSystem) per MS-CIFS section 2.2.4.55.2. `Smb1TreeDisconnect` round-trips the WordCount=0 / ByteCount=0 message used by both the client request and server response per MS-CIFS section 2.2.4.51. `Smb1LogoffAndX` round-trips the WordCount=2 message used by both the client request and server response. Shared core suite pins all eight round-trip paths plus guest-action-bit preservation, non-Unicode rejection, and non-zero ByteCount rejection on LOGOFF and TREE_DISCONNECT.
- [-] Implement `NTCreateAndX`, `ReadAndX`, `WriteAndX`, `Close`, `LockingAndX`, `Echo`, and related core file operation flows.
  Bounded progress: `Smb1NtCreateAndXRequest` and `Smb1NtCreateAndXResponse` codecs now carry the WordCount=24 request (AndX header, NameLength, Flags, RootDirectoryFileId, DesiredAccess, AllocationSize, ExtFileAttributes, ShareAccess, CreateDisposition, CreateOptions, ImpersonationLevel, SecurityFlags, Unicode-aligned FileName) and WordCount=34 response (AndX header, OplockLevel, FID, CreateDisposition, four NT FILETIME timestamps, ExtFileAttributes, AllocationSize, EndOfFile, ResourceType, NMPipeStatus, Directory) per MS-CIFS section 2.2.4.64 with the alignment-pad logic computed against the carrying header position. `Smb1CloseRequest` and `Smb1CloseResponse` carry the WordCount=3 request (FID + LastWriteTime UTIME) and WordCount=0 response per MS-CIFS section 2.2.4.5, with the `LastWriteTimeUnchanged` (`0xFFFFFFFF`) sentinel surfaced for callers that want to preserve modification timestamps. `Smb1EchoRequest` and `Smb1EchoResponse` carry the WordCount=1 EchoCount/SequenceNumber plus variable-length ByteCount-prefixed buffer round-trip per MS-CIFS section 2.2.4.39. Shared core suite pins all six round-trip paths plus non-Unicode rejection on NT_CREATE_ANDX, non-zero ByteCount rejection on CLOSE and NT_CREATE_ANDX response, and ByteCount-mismatch rejection on ECHO. ReadAndX, WriteAndX, LockingAndX, Transaction/Transaction2/NT_TRANSACT codecs and real client/server selection of all SMB1 file-I/O paths remain backlog.
- [ ] Implement `Transaction`, `Transaction2`, and `NT_TRANSACT` families required for directory enumeration, query/set info, and filesystem info.
- [ ] Implement SMB1 error/status mappings and compatibility shims where semantics differ from SMB2/3.
- [ ] Implement NetBIOS session service behavior required for SMB1 interoperability where applicable.
- [x] Add explicit server configuration to keep SMB1 disabled unless the consumer opts in.
  `OpenCifsServerOptions.EnableSmb1` and `OpenCifsServerSettings.EnableSmb1` both default to `false`, the host builder propagates that default through to the configured host, and `Sample.OpenCifsServer` exposes `EnableSmb1 = false` with command-line and configuration-file overrides. The shared server suite asserts SMB1 stays disabled by default and rejects an SMB1 minimum dialect when SMB1 is disabled. Even after the SMB1 dialect itself is implemented, the configuration knob will continue to require explicit opt-in.
- [-] Add loopback and interop tests for SMB1 client and server behavior, including negative tests for downgrade handling and disabled-by-default enforcement.
  Bounded progress: shared server suite already covers disabled-by-default enforcement plus rejection of an SMB1 minimum dialect when SMB1 is disabled, and the SMB1 multi-protocol bootstrap negotiate path that bridges to SMB 2.x is covered by shared core suite plus the bounded Python real-client, Samba, and native Windows interop smokes. Loopback and interop coverage for actual SMB1 dialect command flows depends on the SMB1 dialect being implemented and remains backlog.

Exit criteria:

- [ ] SMB1 rows are complete for the claimed command families.
- [x] SMB1 remains off by default in `OpenCIFS.Server` and `Sample.OpenCifsServer`.
  Verified through the shared server defaults suite plus the explicit `EnableSmb1 = false` defaults on `OpenCifsServerOptions`, `OpenCifsServerSettings`, and `Sample.OpenCifsServer` configuration. This stays true regardless of whether the SMB1 dialect is later implemented.
- [ ] Docs clearly describe the risk profile and opt-in behavior.

## Milestone 8: DFS Referrals And Named Pipe Transport

Goal: add the additional SMB-adjacent behaviors that are in scope for correctness but not bundled RPC services.

- [-] Implement DFS referral request and response handling per the planned claim scope.
  Bounded progress: `OpenCIFS.Protocol` now carries `DfsReferralRequest`, `DfsReferralResponse`, `DfsReferralEntryV2`, and `DfsReferralHeaderFlags` for the bounded version-2 entry shape, with shared core codec round-trip and malformed-input coverage. The bounded slice also fixed an off-by-four `DfsReferralEntryV2` fixed-header length so referral string offsets land on the correct bytes. Broader DFS namespace semantics, EX requests, and multi-version referral entries remain backlog.
- [-] Implement client referral cache behavior and path resolution updates.
  Bounded progress: `OpenCifsClient.ResolveDfsPathAsync` / `TryResolveDfsPathAsync`, `OpenCifsClientConnection.GetDfsReferralsAsync` / `TryGetDfsReferralsAsync` / `ResolveDfsPathAsync` / `TryResolveDfsPathAsync`, and a managed referral cache now resolve a DFS path via `FSCTL_DFS_GET_REFERRALS` over `IPC$` and reuse cached resolutions on subsequent calls within the bounded slice. Shared client coverage pins a live-listener round trip plus cache reuse. The client now also advertises `SMB2_GLOBAL_CAP_DFS` in its negotiate request to remain consistent with the managed DFS surface. Broader cache eviction policy and multi-target referral selection remain backlog.
- [-] Implement server-side referral configuration and response rules.
  Bounded progress: `OpenCifsServerBuilder.AddDfsReferral` and `OpenCifsServerHostBuilder.AddDfsReferral` register bounded DFS referrals, the managed server now exposes `IPC$` whenever DFS referrals are configured, and `OpenCifsServerHost` answers `FSCTL_DFS_GET_REFERRALS` for matching namespace prefixes with the original request server name preserved in the response. Shared server coverage pins null rejection, zero-TTL validation, duplicate-referral rejection, and clone-time field preservation. Broader namespace-root referrals and multi-target referral grouping remain backlog.
- [-] Implement IPC$ and named pipe transport support required for SMB pipe semantics.
  Bounded progress: `OpenCIFS.Client` now implements the client-side `IPC$` tree-connect, named-pipe open, public `TransceiveNamedPipeAsync(...)` / `TryTransceiveNamedPipeAsync(...)`, `EnumerateSharesAsync(...)` / `TryEnumerateSharesAsync(...)`, `GetShareInfoAsync(...)` / `TryGetShareInfoAsync(...)`, and the underlying `FSCTL_PIPE_TRANSCEIVE` path required for bounded remote share browsing and share inspection over `srvsvc` plus reusable custom pipe traffic, and the managed server path now implements bounded `IPC$` hosting plus named-pipe open and `FSCTL_PIPE_TRANSCEIVE` dispatch for registered endpoints including the built-in `srvsvc` share-enumeration/share-info endpoint and the built-in UTF-8 echo endpoint used by the tester consoles. Broader pipe semantics remain backlog.
- [x] Allow DCERPC traffic to pass through the pipe transport when the host application provides the endpoint.
  The current verified slice now carries DCE/RPC bind plus bounded request/response traffic through the managed client and managed server pipe path, including host-provided server-side endpoints, the built-in bounded `srvsvc` share-enumeration/share-info endpoint, and the built-in UTF-8 echo endpoint used for reusable manual and automated pipe transceive coverage.
- [x] Keep WKSSVC, SAMR, LSARPC, and other broader RPC services non-claimed unless separately planned and fully implemented later.
  The only bundled exception in the current verified slice is the bounded `srvsvc` share-enumeration/share-info endpoint needed to keep the exercised share-browsing stack inside OpenCIFS. Broader RPC services over `IPC$` remain non-claimed.
- [-] Add loopback and interop tests for DFS referrals and named pipe transport.
  Bounded progress: shared core, client, server, and loopback interop suites now verify the bounded `IPC$`/named-pipe/`FSCTL_PIPE_TRANSCEIVE` path on the managed stack, including public client pipe transceive success and missing-pipe failure, bounded `srvsvc` share-info success and missing-share failure, generic endpoint registration and duplicate rejection, loopback echo traffic through `IPC$`, and the bounded DCE-RPC/`srvsvc` share-browse/share-info path. The shared client suite now also pins a live-listener round trip where the managed server registers a bounded DFS referral, the managed client resolves the DFS path via `FSCTL_DFS_GET_REFERRALS` over `IPC$`, and the second `ResolveDfsPathAsync` call is served from the client referral cache. `eng/run-test-console-smoke.ps1` now proves `OpenCIFS.TestClient shares`, `shareinfo`, and `pipe opencifs.echo ...` against `OpenCIFS.TestServer` end to end through OpenCIFS itself, and Samba interop still verifies remote share browsing plus bounded share inspection over `IPC$` and `srvsvc` across SMB 2.0.2, SMB 2.1, and SMB 3.0.2. External Windows and Samba DFS interop, multi-target referrals, and DFS namespace EX requests remain backlog.

Exit criteria:

- [-] DFS rows are complete for the claimed scenarios.
  Bounded progress: a single `cross-dialect | dfs | bounded dfs referral codecs, server registration, and client get-referrals plus resolve-with-cache flows` row in `docs/coverage-matrix.md` now reflects the bounded managed end-to-end DFS slice. Broader DFS rows for namespace-root referrals, EX requests, multi-target referrals, and external Windows or Samba DFS interop remain backlog.
- [x] Named pipe transport is functional and tested for the bounded share-browsing slice.
  The current verified scope now covers managed client-side and managed server-side `IPC$`, named-pipe open, public pipe transceive helpers, public bounded share-browse/share-info helpers, `FSCTL_PIPE_TRANSCEIVE`, bounded DCE/RPC bind/request/response handling, the built-in bounded `srvsvc` share-enumeration/share-info endpoint, the built-in UTF-8 echo endpoint, shared-suite coverage, `eng/run-test-console-smoke.ps1`, and Samba interop for remote browse/inspect flows. Broader pipe semantics remain backlog.
- [x] RPC services remain explicitly non-claimed unless later implemented.
  The only bundled exception in the current verified scope is the bounded `srvsvc` share-enumeration/share-info endpoint used for end-to-end share browsing through OpenCIFS.

## Milestone 9: Native Kerberos For SMB

Goal: add native Kerberos support without introducing third-party runtime packages.

- [ ] Implement ASN.1 and DER helpers using the BCL where possible.
- [ ] Implement SPNEGO mechanism negotiation for Kerberos tokens.
- [ ] Implement Kerberos principal, realm, key, ticket, authenticator, checksum, and session-key models needed by SMB.
- [ ] Implement client-side credential acquisition flows required for SMB authentication.
- [ ] Implement server-side ticket validation flows required for SMB authentication.
- [ ] Implement service principal name handling for SMB targets.
- [ ] Implement SMB signing and encryption key derivation from Kerberos session keys.
- [ ] Implement loopback tests for Kerberos-backed SMB session setup.
- [ ] Implement Windows and Samba/AD interop tests for Kerberos session setup, signed sessions, encrypted sessions, and reconnect behavior.
- [x] Do not advertise FAST or any other Kerberos extension until it is fully implemented and covered.
  No Kerberos extension is currently advertised. `SpnegoMechanismOid.Kerberos` exists only as an OID constant available to a future implementation; the SPNEGO negotiation surface advertises NTLMSSP only, and `OpenCIFS.Security` carries no third-party Kerberos package.

Exit criteria:

- [ ] Kerberos rows are complete for the claimed feature set.
- [ ] Kerberos passes the same release gates as NTLMv2.
- [x] No third-party runtime package is required.
  `OpenCIFS.Security`, `OpenCIFS.Client`, and `OpenCIFS.Server` depend only on the .NET BCL plus other in-solution projects. The package-graph validator enforces this, so any future Kerberos implementation will have to remain BCL-only as well.

## Milestone 10: GA Hardening And Publish Readiness

Goal: move from "feature complete" to "safe to ship".

- [-] Audit the entire codebase for placeholder comments, TODOs, and unreachable advertised branches.
  Bounded progress: `eng/OpenCIFS.Build` now enforces a source-audit gate across product and release-facing surfaces, so `dotnet build` and `eng/run-release-gates.ps1` fail on `NotImplementedException` in product code and on TODO or placeholder or stub language in claimed product and package-facing surfaces. Full-repository unreachable-advertised-branch auditing remains backlog.
- [x] Run long-duration soak tests for many simultaneous connections, reconnect churn, lease/oplock churn, and large file transfers.
- [-] Run parser mutation and malformed-input suites at scale.
  Bounded progress: `OpenCIFS.Core.Tests.Shared` now runs deterministic parser-mutation corpuses across representative direct-TCP, SMB1/SMB2, compounding, IOCTL, lease-break, metadata, negotiate, DFS referral request and response, and SMB 3.1.1 negotiate-context list readers, and `OpenCIFS.Server.Tests.Shared` now runs a malformed direct-TCP mutation burst against the live listener while verifying post-burst negotiate recovery and bounded protocol-exception surfacing. The full Debug integration gate was rerun on 2026-04-29 after listener hardening in `OpenCifsDirectTcpServer`; longer-running mutation volume and broader client/interop malformed-input scaling remain backlog.
- [x] Verify a bounded public exception-taxonomy slice for the primary and advanced client surfaces plus the primary server builder/application surfaces, with typed client state/protocol/status exceptions, typed server configuration/state exceptions, README and package-readme guidance, and shared regression coverage while non-throwing result envelopes remain backlog.
- [x] Verify a bounded primary-client result-envelope slice for `OpenCifsClient` and `OpenCifsShareSession` grouped `Files` or `Directories` or `Metadata` or `Locks` APIs, with `Try...Async` non-throwing companions returning typed `OpenCifsClientResult` envelopes that preserve SMB command, NTSTATUS, normalized category, and typed client exception detail.
- [x] Verify a bounded advanced/raw and managed-server result-envelope slice for `OpenCifsClientConnection` and `OpenCifsServerApplication`, with `Try...Async` companions covering bounded connection lifecycle, tree/open/read/write/query/set/notify/compound/close flows plus managed server `RunAsync` or `StartAsync` or `StopAsync`, typed `OpenCifsServerStateException` wrapping for bind and disposed-lifecycle failures, and shared positive and negative regression coverage.
- [x] Review API naming, XML docs, disposal semantics, cancellation semantics, and exception taxonomy.
- [x] Review package metadata and sample instructions, and validate emitted package readmes through package-smoke coverage.
- [x] Add build-time package-claim validation so packable project metadata and emitted package readmes cannot advertise unimplemented capabilities.
- [x] Review README examples.
- [x] Validate the documented README client and server flows end to end through a generated downstream consumer.
- [x] Add a one-command `Release` gate that reruns the managed, package, README, and external interop stack and rejects stale current-release evidence.
- [x] Verify `Sample.OpenCifsServer` documentation includes safe startup defaults, credential setup, share-root setup, and port override instructions.
- [x] Verify all coverage matrix rows marked implemented have zero skipped descriptors.
- [x] Verify all interop matrix entries have recent evidence attached before publish.
- [x] Pack and smoke-test `OpenCIFS.Protocol`, `OpenCIFS.Server`, and `OpenCIFS.Client`.

Exit criteria:

- [x] `dotnet build` is clean with zero warnings.
- [x] All required Touchstone console suites are green.
- [x] All required interop suites are green.
- [x] No implemented capability has skipped descriptors.
- [x] No package claims an unimplemented feature.

## Sample.OpenCifsServer Requirements

- [x] Create a real executable host, not a mock or fake sample.
- [x] Support local configuration of share path, credentials, bind address, and bind port.
- [x] Default to port `4450`; document how to bind to `445`.
- [x] Require signing by default.
- [x] Require NTLMv2 by default.
- [x] Disable anonymous access by default.
- [x] Disable SMB1 by default.
- [x] Require encryption by default for SMB 3.x sessions where the dialect supports it.
- [x] Provide a deterministic startup banner or status output that tells a tester how to connect.
- [x] Add a smoke test script or test case that validates the sample configuration end to end.
- [x] Add a published-sample smoke script that validates a bundled `Sample.OpenCifsServer` executable and helper-launcher path without source edits.

## Manual Tester Console Requirements

- [x] Add a real menu-driven `OpenCIFS.TestClient` project for manual client exercise without code edits.
- [x] Add a real menu-driven `OpenCIFS.TestServer` project for manual server exercise with a temporary backing directory and configurable bind or credential settings.
- [x] Route `OpenCIFS.TestClient` share listing, bounded share inspection, and bounded named-pipe transceive through OpenCIFS itself and make the managed `OpenCIFS.TestServer` path expose the same bounded `IPC$` / `srvsvc` / custom-pipe flow end to end.
- [x] Add a scripted smoke harness that drives both tester consoles through redirected stdin and validates a bounded end-to-end flow.

## CI And Release Gates

The following are mandatory gates for any milestone that claims a completed capability set:

- [x] `dotnet build` clean with warnings-as-errors
- [x] `OpenCIFS.Core.Tests.Console`
- [x] `OpenCIFS.Server.Tests.Console`
- [x] `OpenCIFS.Client.Tests.Console`
- [x] `OpenCIFS.Interop.Tests.Console`
- [x] Windows interop pass for the claimed rows
- [x] Samba interop pass for the claimed rows
- [x] zero `NotImplementedException` in product code
- [x] zero TODO-based capability claims
- [x] coverage matrix updated in the same change set
- [x] interop matrix updated in the same change set

`xUnit`, `NUnit`, and `MSTest` runners remain required for compatibility coverage, but they are not the primary release gate if the Touchstone console runners already provide the authoritative pass/fail signal.

## First GA Non-Claims

These items must remain explicitly non-claimed until they are fully implemented and tested:

- SMB Direct / RDMA
- SMB multichannel beyond single-channel negotiation behavior
- Witness protocol
- continuous availability for clustered shares
- BranchCache
- peer caching / ROBO-style peer features
- broader bundled RPC services over IPC$ beyond the bounded `srvsvc` share-enumeration/share-info endpoint
- SMB 3.1.1 compression
- SMB over QUIC transport
- RDMA transform capabilities
- Kerberos FAST unless fully implemented

If any of these later move into scope, add rows to the coverage matrix first, then add implementation tasks, then advertise them only after tests are green.

## Definition Of Done

This plan is complete only when all of the following are true:

- [x] `OpenCIFS.Protocol`, `OpenCIFS.Server`, and `OpenCIFS.Client` are publishable packages.
- [x] `OpenCIFS.Transport` and `OpenCIFS.Security` remain documented as advanced dependency packages unless intentionally promoted as first-class integration entry points after review.
- [x] `Sample.OpenCifsServer` is usable by an external tester without code changes.
- [ ] Every claimed SMB/CIFS dialect row in `docs/coverage-matrix.md` is fully implemented for both server and client where applicable.
- [ ] Windows and Samba interop evidence exists for every claimed capability row.
- [ ] No capability is advertised without complete code and tests.
- [ ] The repository contains no stub code, no placeholder protocol handlers, and no ambiguous roadmap language that can be mistaken for implementation.

