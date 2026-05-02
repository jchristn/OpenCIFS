# OpenCIFS Compatibility Plan

Use this file as a live implementation checklist. Keep the section order in sync with `C:\Code\OpenNFS\COMPATIBILITY.md`, and annotate progress inline with `[ ]`, `[-]`, or `[x]` plus short notes, dates, or PR links.

## Northstar

OpenCIFS should converge on the same consumer journey as OpenNFS without hiding CIFS/SMB-specific semantics:

1. Build validated immutable settings with `OpenCifsClientBuilder`.
2. Create `OpenCifsClient` as the primary client entry point.
3. Call `ConnectAsync(...)` / `DisconnectAsync(...)` for client lifecycle.
4. Open a protocol-named namespace session with `OpenShareAsync(...)` and work through `OpenCifsShareSession`.
5. Use path-first grouped APIs on the session: `Files`, `Directories`, `Metadata`, `Locks`.
6. Use a separate advanced surface for raw connection, session, tree, open, and protocol-specific flows.

Target client usage:

```csharp
var client = new OpenCifsClientBuilder()
    .WithServer("files.example.test")
    .Build();

await client.ConnectAsync(credential, ct);
await using var share = await client.OpenShareAsync("data", ct);

var bytes = await share.Files.ReadAllBytesAsync("/docs/readme.txt", ct);
var stat = await share.Metadata.GetAttributesAsync("/docs/readme.txt", ct);

await client.DisconnectAsync(ct);
```

Target server usage:

```csharp
var app = new OpenCifsServerBuilder()
    .AddShare("data", share => share.UseLocalFileSystem(rootPath))
    .BuildApplication();

await app.RunAsync(ct);
```

The goal is not identical protocol nouns. The goal is identical consumer flow and mirrored public shape wherever protocol truth allows it.

## Non-goals

- Do not create a shared abstractions package between OpenCIFS and OpenNFS in this phase.
- Do not replace CIFS/SMB terms such as share open, tree connect, or NTSTATUS with fake cross-protocol terminology.
- Do not remove raw or protocol-exact APIs; they remain required for full coverage.
- Do not force CIFS to mirror NFS capability counts or backend interface layout exactly.
- Do not collapse all errors into protocol-agnostic exceptions that hide NTSTATUS or SMB context.
- Do not preserve current public APIs for compatibility if they materially block the northstar; this is pre-release software.

## Current gaps

- The primary CIFS happy path is now aligned around builder -> client -> share session, and the advanced/raw layer now includes explicit bounded realistic compound helpers plus bounded SMB 2.1 lease-backed durable reconnect on `OpenCifsClientConnection`, but the older facade and lower-level connection/session/tree primitives still coexist and need long-term boundary cleanup.
- Typed client and server failure hierarchies now exist through `OpenCifsClientException`, `OpenCifsClientStateException`, `OpenCifsClientProtocolException`, `OpenCifsStatusException`, `OpenCifsServerException`, `OpenCifsServerConfigurationException`, and `OpenCifsServerStateException`. The primary client happy path plus the bounded advanced/raw `OpenCifsClientConnection` surface now expose non-throwing `Try...Async` result envelopes through `OpenCifsClientResult` / `OpenCifsClientResult<T>`, and `OpenCifsServerApplication` now exposes bounded managed-lifecycle `TryRunAsync` / `TryStartAsync` / `TryStopAsync` companions through `OpenCifsServerResult`.
- Documentation now leads with the aligned consumer journey and explicitly separates the advanced/raw surface, but final parity cleanup across every repo doc remains incomplete.
- Test projects now pin the first-pass public shape, README snippets, dedicated client samples, normalized error-category behavior, bounded primary-client `Try...Async` result-envelope shape, bounded advanced/raw `OpenCifsClientConnection` `Try...Async` shape, and bounded managed-server lifecycle result-envelope shape, but they do not yet enforce mirrored OpenNFS parity work.

## Planned refactors

### 1. Client primary surface

- [x] Introduce or finalize `OpenCifsClientBuilder` as the only recommended client construction path.
- [x] Replace mutable-options-first guidance with validated immutable settings produced by the builder.
- [x] Promote `OpenCifsClient` as the primary public type and demote `OpenCifsClientFacade` to transitional or advanced status once the new surface exists.
- [x] Standardize `OpenCifsClient.ConnectAsync(OpenCifsClientCredential credential, CancellationToken)` and `DisconnectAsync(CancellationToken)` as the canonical client lifecycle methods.
- [x] Decide whether any existing low-level connect/session entry points should remain public but undocumented as happy-path APIs.

### 2. Namespace session and path-first operations

- [x] Introduce `OpenCifsShareSession` in `src/OpenCIFS.Client` as the primary share-scoped unit of work.
- [x] Standardize `OpenShareAsync(shareName, CancellationToken)` on the connected client as the primary session-open path.
- [x] Expose grouped session members with the same shape as OpenNFS: `Files`, `Directories`, `Metadata`, and `Locks`.
- [x] Add or reshape path-first operations so common usage does not require consumers to manage tree handles or repeat the share name on every call.
- [x] Preserve advanced connection/session/tree/open APIs as an explicit advanced layer rather than the default happy path.
- [x] Align parameter ordering and cancellation-token placement with OpenNFS for all comparable operations.

### 3. Result envelopes and exceptions

- [x] Introduce a typed exception hierarchy for OpenCIFS client and server surfaces.
- [x] Ensure every typed exception carries both a native SMB/NTSTATUS code and a normalized category such as `NotFound`, `AccessDenied`, `Conflict`, `Unsupported`, `IoError`, or `ProtocolError`.
- [x] Add a non-throwing result-envelope pattern for operations where protocol detail should be preserved instead of flattened into generic failure.
  Verified scope: the primary `OpenCifsClient` -> `OpenCifsShareSession` happy path plus the bounded advanced/raw `OpenCifsClientConnection` surface now expose `Try...Async` companions that return `OpenCifsClientResult` / `OpenCifsClientResult<T>` and preserve typed client exceptions, SMB2 command, NTSTATUS, and normalized error categories. The managed server lifecycle now also exposes bounded `OpenCifsServerApplication.TryRunAsync(...)`, `TryStartAsync(...)`, and `TryStopAsync(...)` companions returning `OpenCifsServerResult` with typed `OpenCifsServerException` detail.
- [x] Standardize the naming convention for throwing and non-throwing method pairs with OpenNFS before implementation lands in either repo.
  The current compatibility target is `MethodAsync(...)` for throwing APIs and `TryMethodAsync(...)` for non-throwing envelopes.
- [x] Ensure high-level exceptions still retain enough SMB command and context detail for diagnostics.

### 4. Server application alignment

- [x] Confirm `OpenCifsServerBuilder.BuildApplication()` is the primary server construction path in `src/OpenCIFS.Server`.
- [x] Confirm `OpenCifsServerApplication` with `StartAsync`, `StopAsync`, and `RunAsync` is the primary documented server host surface.
- [x] Introduce a clearer `OpenCifsServer` configuration/runtime model if it materially improves parity with OpenNFS builder -> server -> application flow.
  `OpenCifsServerBuilder.BuildSettings()` now returns immutable `OpenCifsServerSettings`, `Build()` now returns a configured `OpenCifsServer`, and the documented server path now follows builder -> server -> application without removing the existing advanced host-builder surface.
- [x] Keep the aligned primary server builder expressive enough for current managed-path feature slices without forcing consumers back to raw mutable options.
  `OpenCifsServerBuilder` now exposes `WithSmb3EncryptionRequired(...)` so the bounded opt-in SMB 3.0 / SMB 3.0.2 negotiate and AES-CMAC signing slice is reachable from the aligned builder surface instead of only through manual option mutation.
- [x] Refactor backend composition toward one mandatory filesystem contract plus an open-ended set of optional capability contracts and discoverable flags.
- [x] Keep built-in local filesystem-backed shares as a first-class setup path.

### 5. Advanced surface boundaries

- [x] Define which namespaces, types, or builder options represent the advanced/raw surface.
- [x] Make raw connection/session/tree/open workflows discoverable but clearly secondary in quickstarts.
- [x] Ensure advanced APIs preserve full protocol fidelity and are not simplified into the high-level shape.
- [x] Document how high-level share-session operations map onto advanced SMB concepts for developers who need to drop down a layer.

### 6. Documentation and samples

- [x] Update `README.md` so its first client example uses the aligned builder -> client -> share session -> grouped path API flow.
- [x] Update `README.md` so its first server example uses `OpenCifsServerBuilder.BuildApplication()` and `RunAsync`.
- [x] Update `OPENCIFS.md` to document the layered model: high-level share-session APIs first, advanced protocol APIs second.
- [x] Update `docs/coverage-matrix.md` and `docs/interop-matrix.md` where needed so they reference the aligned public surface rather than only lower-level primitives.
- [x] Add a short "OpenCIFS and OpenNFS usage parity" section to `README.md` or `OPENCIFS.md` so consumers see the intentional convergence.
- [x] Document credential injection point, exception/result-envelope behavior, and the advanced/raw escape hatches.
  Credential injection, typed client/server exception behavior, the primary non-throwing `Try...Async` result-envelope path, the bounded advanced/raw `OpenCifsClientConnection` `Try...Async` surface, the managed `OpenCifsServerApplication` lifecycle result-envelope path, and the advanced/raw escape hatches, including the bounded realistic compound helpers on `OpenCifsClientConnection`, are now documented on the primary path.
- [x] Update `src/Sample.OpenCifsServer` to use the aligned server application surface.
- [x] Update client-facing sample code in `src/OpenCIFS.Client.Tests.Console` or a dedicated sample so a consumer can copy one happy-path example without touching low-level primitives.

### 7. Tests and approval gates

- [x] Add API-shape approval or reflection tests in `src/OpenCIFS.Client.Tests.Xunit`, `src/OpenCIFS.Server.Tests.Xunit`, or shared test projects that validate the aligned public naming:
  - [x] `OpenCifsClientBuilder`
  - [x] `OpenCifsClient`
  - [x] `ConnectAsync` / `DisconnectAsync`
  - [x] `OpenCifsShareSession`
  - [x] `Files` / `Directories` / `Metadata` / `Locks`
  - [x] `OpenCifsServerApplication`
- [x] Add tests for share-session path-first flows so common operations do not regress back toward tree-handle-centric usage.
- [x] Add tests for exception mapping and normalized category coverage.
- [x] Add tests for result-envelope behavior and parity with the OpenNFS naming convention.
  OpenCIFS shared client and server suites now pin the `Try...Async` naming convention plus positive and negative primary-surface, advanced/raw connection-surface, and managed-server lifecycle result-envelope behavior. Mirrored OpenNFS coverage remains deferred.
- [x] Add smoke tests that compile and execute the canonical README client and server snippets, or equivalent sample-based verification if snippet tests are not practical.
- [-] Mirror the same acceptance-test concepts in OpenNFS so both repos can prove parity rather than just claim it.
  OpenCIFS-side acceptance tests are complete: shared client and server suites pin `OpenCifsClientBuilder`, `OpenCifsClient`, `OpenCifsShareSession`, grouped `Files`/`Directories`/`Metadata`/`Locks` APIs, `OpenCifsServerApplication` lifecycle, exception mapping with normalized error categories, `Try...Async` result-envelope behavior across primary, advanced/raw, and managed-server lifecycle surfaces, and the canonical README client/server snippets through `eng/run-readme-smoke.ps1`. Mirroring the matching acceptance-test concepts inside the OpenNFS repository is cross-repo follow-up work that OpenCIFS cannot land directly; it remains tracked in `C:\Code\OpenNFS\COMPATIBILITY.md` per the section-order convention referenced at the top of this file.

## Acceptance criteria

- The documented happy path in OpenCIFS matches the documented happy path in OpenNFS at the structural level:
  - build settings
  - create client
  - connect
  - open protocol-named namespace session
  - use grouped path-first APIs
  - disconnect
- `OpenCifsShareSession` exists and is the primary unit for common file operations.
- Session members use the same names and parameter-order conventions as the OpenNFS session surface wherever protocol truth allows it.
- Throwing APIs and result-envelope APIs exist in parallel on the primary client happy path, the bounded advanced/raw `OpenCifsClientConnection` surface, and the bounded managed `OpenCifsServerApplication` lifecycle surface, and both repos use `MethodAsync(...)` / `TryMethodAsync(...)` as the compatibility target naming convention for the pair.
- Typed exceptions expose both NTSTATUS and normalized error categories.
- `OpenCifsServerApplication` is the primary server host surface, and the builder/application story matches OpenNFS.
- `README.md`, `OPENCIFS.md`, relevant `docs/` pages, and sample code all show the aligned usage pattern rather than the older low-level-first flow.
- Automated tests enforce API-shape parity, exception mapping expectations, and the canonical usage snippets.
- Advanced/raw APIs still exist and still expose full protocol truth.

## Resolved questions

- **How much of `OpenCifsClientFacade` should remain public after `OpenCifsClient` and `OpenCifsShareSession` become the primary surface?** Resolved: `OpenCifsClientFacade` stays public as a transitional/advanced surface alongside the aligned primary client. The shared client API-shape regression suite explicitly verifies that `OpenCifsClientFacade` carries no `OpenCifsPreviewAttribute` and continues to track the stable direct-TCP connection surface, while the README, package readmes, and `OPENCIFS.md` lead with the `OpenCifsClientBuilder` -> `OpenCifsClient` -> `OpenCifsShareSession` happy path. The facade can be revisited for narrowing once both repositories stabilize, but the current-pass decision is to keep it.
- **Should the compatibility approval tests live entirely in each repo, or should both repos read a shared manifest later once the shapes stabilize?** Resolved: each repo currently owns its own acceptance tests so the suites can evolve independently while the public shapes settle. A shared manifest is deferred follow-up work and can be revisited after both sides reach steady state on the primary client surface, the advanced/raw surface, the result-envelope shape, and the typed-exception taxonomy.
- **Which optional CIFS server capabilities should get first-class adapter contracts in the initial aligned pass versus later follow-up work?** Resolved: the initial aligned pass exposes one mandatory filesystem contract through `OpenCifsServerFileSystemShare` plus typed adapter contracts and discoverable capability flags for the bounded slices already verified end to end (request callbacks, named-pipe endpoints with the bounded built-in `srvsvc` share-enumeration / `srvsvc` share-info plus UTF-8 echo endpoints, DFS referrals). Broader optional-capability contracts (durable handles tied to clustered shares, witness, DFS namespace roots beyond the bounded slice, broader RPC services) stay backlog until they are fully implemented so the adapter contracts only land when there is a real implementation to bind them to.
