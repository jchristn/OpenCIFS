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
- [ ] Add test utilities for temp shares, temp credentials, packet capture helpers, golden vectors, and deterministic clocks.
- [ ] Add negative-test helpers for malformed frames, signature failures, replay attempts, invalid credits, and invalid state transitions.
- [ ] Add long-run soak test harnesses for connection churn, reconnect, and large I/O.

### Workstream C: Interop Lab

- [x] Add a bounded real-client smoke workflow for `Sample.OpenCifsServer` using a non-loopback SMB client and record the evidence in `docs/interop-matrix.md`.
- [x] Stand up a Samba test environment that can run in CI or a reproducible lab script.
- [x] Stand up a Windows client test environment for mounting and exercising `Sample.OpenCifsServer`.
- [ ] Stand up a Windows server test environment for validating `OpenCIFS.Client`.
- [x] Capture exact OS and Samba versions in `docs/interop-matrix.md`.
- [ ] Automate smoke interop runs for every merged dialect milestone.
- [ ] Automate deeper nightly interop runs for durable reconnect, encryption, and long I/O scenarios.

### Workstream D: Documentation And Release Discipline

- [ ] Keep `README.md` aligned with actual implemented capabilities only.
- [ ] Update `CHANGELOG.md` per milestone.
- [ ] Keep `docs/coverage-matrix.md` current in the same PR as the code change.
- [ ] Keep `docs/interop-matrix.md` current with last verified environments and dates.
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
- [ ] Implement compounding support for valid SMB 2.0.2 request chains.
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
- [ ] Implement create dispositions, create options, share modes, delete-pending behavior, rename behavior, allocation size, end-of-file updates, and timestamp semantics.
- [ ] Complete the broader SMB 2.0.2 handle-table, durable-state, and reconnect behavior that remains outside the bounded durable batch-oplock reconnect slice.
- [x] Implement error mapping so NTSTATUS behavior is explicit and tested.

### Server Surface

- [x] Define the server host API for listener creation, share registration, authentication configuration, and lifecycle control.
- [x] Define backend contracts for files, directories, metadata, locking, notifications, and named streams where supported.
- [x] Implement a local filesystem-backed share provider for `Sample.OpenCifsServer`.
- [x] Verify a bounded server-surface slice for `OpenCifsServerHostBuilder`, explicit local filesystem share registration, duplicate-share rejection, and suppression of the implicit legacy options share whenever explicit share registrations are present.
- [x] Verify a bounded `Sample.OpenCifsServer` filesystem-provider slice that registers the configured local share through the builder-backed host surface and passes loopback plus real-client smoke validation.
- [x] Implement typed callback hooks for authenticated session completion, tree connect, create, query directory, set info, and IOCTL requests that require application control rather than fixed filesystem behavior.
- [x] Enforce safe defaults: signing required, NTLMv2 only, anonymous disabled, SMB1 disabled, bind port default `4450`.

### Client Surface

- [x] Define the low-level client session API for connect, authenticate, tree connect, open, read, write, query, set, enumerate, and close.
- [x] Define the high-level client facade for common file and directory operations.
- [x] Verify a bounded preview direct-TCP client facade for connect, authenticate, echo, create directory, write file, read file, and directory enumeration flows against `OpenCifsServer`.
- [x] Extend the bounded preview direct-TCP client facade with metadata query, rename, and file or empty-directory delete flows against `OpenCifsServer`.
- [x] Extend the bounded preview direct-TCP client facade with bounded `FILE_BASIC_INFORMATION` and `FILE_END_OF_FILE_INFORMATION` mutation flows against `OpenCifsServer`.
- [x] Start the direct-TCP ergonomic client facade behind an explicit preview marker until the non-preview low-level connection surface and common-operations coverage are complete.
- [x] Verify a bounded multi-client direct-TCP slice for `OpenCifsDirectTcpServer` shared state and client surfaces: cross-connection async `CHANGE_NOTIFY` completion, high-level facade notify waits, read-share success, conflicting share-access rejection, and cross-session byte-range lock-conflict rejection.

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

Exit criteria:

- [ ] `OpenCIFS.Server` and `OpenCIFS.Client` both complete the SMB 2.0.2 coverage rows with zero skipped descriptors for implemented items.
- [ ] `Sample.OpenCifsServer` can be mounted and exercised from Windows and Samba using the documented defaults.
- [ ] `OpenCIFS.Client` can exercise equivalent flows against Samba and Windows servers.

## Milestone 4: SMB 2.1 Lockstep Enhancements

Goal: add SMB 2.1 semantics without splitting the implementation between client and server.

- [x] Implement SMB 2.1 negotiate behavior and dialect-specific capability handling.
- [x] Verify the existing managed session, tree, file-I/O, metadata, notification, locking, oplock, and bounded durable-reconnect surface under negotiated SMB 2.1 in loopback plus bounded Python real-client, Samba, and native Windows client smoke flows.
- [x] Implement a bounded SMB 2.1 leasing slice with `RqLs` create contexts, read/write/handle lease grant handling, signed lease-break notifications and acknowledgments, direct-TCP client wait-and-ack handling, and same-lease-key path-mismatch rejection.
- [x] Implement bounded large MTU support and multi-credit large read/write behavior, including SMB 2.1 `SMB2_GLOBAL_CAP_LARGE_MTU` negotiation, managed credit-window growth, multi-credit request validation, and verified `200000`-byte large-transfer coverage across loopback plus bounded Python real-client, Samba, and native Windows client smoke flows.
- [ ] Implement durable reconnect semantics required by SMB 2.1.
- [ ] Expand compounding tests for realistic open-read-close, create-query-close, and create-write-flush-close chains.
- [ ] Expand loopback and interop tests for broader lease scenarios, reconnect, and large transfers.
- [ ] Update the sample server and documentation only if any defaults or limits change.

Exit criteria:

- [x] SMB 2.1 rows in the coverage matrix are complete for both client and server.
- [ ] Large I/O, lease behavior, and reconnect paths are green in loopback and interop suites.

## Milestone 5: SMB 3.0 And SMB 3.0.2 Lockstep Enhancements

Goal: add SMB 3.x security and durability features that are in scope for first GA.

- [ ] Implement SMB 3.0/3.0.2 negotiate behavior and capability flags.
- [ ] Implement AES-CMAC signing selection where negotiated.
- [ ] Implement AES-128-CCM encryption and decryption flows.
- [ ] Implement secure negotiate validation.
- [ ] Implement durable handles v2 and reconnect flows that do not rely on clustered continuous availability.
- [ ] Implement session and tree behavior changes required by SMB 3.0/3.0.2.
- [ ] Add loopback tests for encrypted sessions, encrypted read/write, encrypted compounding, and durable reconnect.
- [ ] Add Windows and Samba interop tests for signing required and encryption required scenarios.
- [ ] Keep continuous availability, persistent handles tied to clustered shares, and multichannel out of claim scope unless fully implemented later.

Exit criteria:

- [ ] SMB 3.0 and SMB 3.0.2 in-scope rows are complete with zero skipped descriptors for implemented items.
- [ ] Encryption-required sessions work in loopback and interop tests.
- [ ] Secure negotiate downgrade tests are green.

## Milestone 6: SMB 3.1.1 Core Negotiate Contexts

Goal: complete the core SMB 3.1.1 functionality that is required for modern secure interoperability.

- [ ] Implement preauth integrity negotiation and transcript hashing.
- [ ] Implement signing capability negotiation with algorithm selection by negotiated `SigningAlgorithmId`.
- [ ] Implement AES-GMAC signing where negotiated.
- [ ] Implement encryption capability negotiation for AES-128-GCM, AES-128-CCM, AES-256-GCM, and AES-256-CCM as supported by the target frameworks and interoperability matrix.
- [ ] Implement `SMB2_NETNAME_NEGOTIATE_CONTEXT_ID`.
- [ ] Add downgrade and tamper tests for negotiate contexts and preauth integrity.
- [ ] Add loopback and interop tests for SMB 3.1.1 signed and encrypted sessions using the negotiated algorithms.
- [ ] Add explicit coverage rows for these backlog contexts with `advertised=false` and `implemented=false` until they are done:
- [ ] `SMB2_COMPRESSION_CAPABILITIES`
- [ ] `SMB2_TRANSPORT_CAPABILITIES`
- [ ] `SMB2_RDMA_TRANSFORM_CAPABILITIES`

Exit criteria:

- [ ] Core SMB 3.1.1 rows are complete and green.
- [ ] Compression, QUIC transport, and RDMA remain clearly non-advertised unless separately completed later.

## Milestone 7: SMB1/CIFS Compatibility Layer

Goal: implement SMB1/CIFS thoroughly while keeping it opt-in and off by default.

- [ ] Implement SMB1 dialect negotiation for the required dialect set, including `LANMAN1.0` and `NT LM 0.12` if claimed.
- [ ] Implement SMB1 session setup, tree connect, and logoff flows.
- [ ] Implement `NTCreateAndX`, `ReadAndX`, `WriteAndX`, `Close`, `LockingAndX`, `Echo`, and related core file operation flows.
- [ ] Implement `Transaction`, `Transaction2`, and `NT_TRANSACT` families required for directory enumeration, query/set info, and filesystem info.
- [ ] Implement SMB1 error/status mappings and compatibility shims where semantics differ from SMB2/3.
- [ ] Implement NetBIOS session service behavior required for SMB1 interoperability where applicable.
- [ ] Add explicit server configuration to keep SMB1 disabled unless the consumer opts in.
- [ ] Add loopback and interop tests for SMB1 client and server behavior, including negative tests for downgrade handling and disabled-by-default enforcement.

Exit criteria:

- [ ] SMB1 rows are complete for the claimed command families.
- [ ] SMB1 remains off by default in `OpenCIFS.Server` and `Sample.OpenCifsServer`.
- [ ] Docs clearly describe the risk profile and opt-in behavior.

## Milestone 8: DFS Referrals And Named Pipe Transport

Goal: add the additional SMB-adjacent behaviors that are in scope for correctness but not bundled RPC services.

- [ ] Implement DFS referral request and response handling per the planned claim scope.
- [ ] Implement client referral cache behavior and path resolution updates.
- [ ] Implement server-side referral configuration and response rules.
- [ ] Implement IPC$ and named pipe transport support required for SMB pipe semantics.
- [ ] Allow DCERPC traffic to pass through the pipe transport when the host application provides the endpoint.
- [ ] Do not bundle SRVSVC, WKSSVC, SAMR, LSARPC, or other RPC services unless separately planned and fully implemented later.
- [ ] Add loopback and interop tests for DFS referrals and named pipe transport.

Exit criteria:

- [ ] DFS rows are complete for the claimed scenarios.
- [ ] Named pipe transport is functional and tested.
- [ ] RPC services remain explicitly non-claimed unless later implemented.

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
- [ ] Do not advertise FAST or any other Kerberos extension until it is fully implemented and covered.

Exit criteria:

- [ ] Kerberos rows are complete for the claimed feature set.
- [ ] Kerberos passes the same release gates as NTLMv2.
- [ ] No third-party runtime package is required.

## Milestone 10: GA Hardening And Publish Readiness

Goal: move from "feature complete" to "safe to ship".

- [ ] Audit the entire codebase for placeholder comments, TODOs, and unreachable advertised branches.
- [ ] Run long-duration soak tests for many simultaneous connections, reconnect churn, lease/oplock churn, and large file transfers.
- [ ] Run parser mutation and malformed-input suites at scale.
- [ ] Review API naming, XML docs, disposal semantics, cancellation semantics, and exception taxonomy.
- [x] Review package metadata and sample instructions, and validate emitted package readmes through package-smoke coverage.
- [x] Review README examples.
- [x] Validate the documented README client and server flows end to end through a generated downstream consumer.
- [x] Add a one-command `Release` gate that reruns the managed, package, README, and external interop stack and rejects stale current-release evidence.
- [x] Verify `Sample.OpenCifsServer` documentation includes safe startup defaults, credential setup, share-root setup, and port override instructions.
- [ ] Verify all coverage matrix rows marked implemented have zero skipped descriptors.
- [ ] Verify all interop matrix entries have recent evidence attached before publish.
- [x] Pack and smoke-test `OpenCIFS.Protocol`, `OpenCIFS.Server`, and `OpenCIFS.Client`.

Exit criteria:

- [ ] `dotnet build` is clean with zero warnings.
- [ ] All required Touchstone console suites are green.
- [ ] All required interop suites are green.
- [ ] No implemented capability has skipped descriptors.
- [ ] No package claims an unimplemented feature.

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

## CI And Release Gates

The following are mandatory gates for any milestone that claims a completed capability set:

- [ ] `dotnet build` clean with warnings-as-errors
- [ ] `OpenCIFS.Core.Tests.Console`
- [ ] `OpenCIFS.Server.Tests.Console`
- [ ] `OpenCIFS.Client.Tests.Console`
- [ ] `OpenCIFS.Interop.Tests.Console`
- [ ] Windows interop pass for the claimed rows
- [ ] Samba interop pass for the claimed rows
- [ ] zero `NotImplementedException` in product code
- [ ] zero TODO-based capability claims
- [ ] coverage matrix updated in the same change set
- [ ] interop matrix updated in the same change set

`xUnit`, `NUnit`, and `MSTest` runners remain required for compatibility coverage, but they are not the primary release gate if the Touchstone console runners already provide the authoritative pass/fail signal.

## First GA Non-Claims

These items must remain explicitly non-claimed until they are fully implemented and tested:

- SMB Direct / RDMA
- SMB multichannel beyond single-channel negotiation behavior
- Witness protocol
- continuous availability for clustered shares
- BranchCache
- peer caching / ROBO-style peer features
- bundled RPC services over IPC$
- SMB 3.1.1 compression
- SMB over QUIC transport
- RDMA transform capabilities
- Kerberos FAST unless fully implemented

If any of these later move into scope, add rows to the coverage matrix first, then add implementation tasks, then advertise them only after tests are green.

## Definition Of Done

This plan is complete only when all of the following are true:

- [ ] `OpenCIFS.Protocol`, `OpenCIFS.Server`, and `OpenCIFS.Client` are publishable packages.
- [ ] `OpenCIFS.Transport` and `OpenCIFS.Security` remain documented as advanced dependency packages unless intentionally promoted as first-class integration entry points after review.
- [ ] `Sample.OpenCifsServer` is usable by an external tester without code changes.
- [ ] Every claimed SMB/CIFS dialect row in `docs/coverage-matrix.md` is fully implemented for both server and client where applicable.
- [ ] Windows and Samba interop evidence exists for every claimed capability row.
- [ ] No capability is advertised without complete code and tests.
- [ ] The repository contains no stub code, no placeholder protocol handlers, and no ambiguous roadmap language that can be mistaken for implementation.

