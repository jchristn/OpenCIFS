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

- The current CIFS client story is split between facade-style usage and lower-level connection/session/tree primitives.
- Mutable client options are still part of the main public story instead of builder-produced immutable validated settings.
- There is no public `OpenCifsShareSession` that makes share-scoped work the primary unit of consumption.
- Common file operations still require too much share-specific or low-level context compared with the target OpenNFS flow.
- Advanced SMB concepts are too close to the default public surface for common consumers.
- The server application model is closer to the target than OpenNFS, but the documented primary surface still needs to align exactly with the shared northstar.
- Error handling does not yet offer a consistent typed exception model with both NTSTATUS and normalized categories.
- Documentation is spread across `README.md`, `OPENCIFS.md`, and `docs/`, but not yet organized around the same consumer journey OpenNFS should present.
- Test projects do not yet enforce API-shape parity with OpenNFS at the API, docs, and sample levels.

## Planned refactors

### 1. Client primary surface

- [ ] Introduce or finalize `OpenCifsClientBuilder` as the only recommended client construction path.
- [ ] Replace mutable-options-first guidance with validated immutable settings produced by the builder.
- [ ] Promote `OpenCifsClient` as the primary public type and demote `OpenCifsClientFacade` to transitional or advanced status once the new surface exists.
- [ ] Standardize `OpenCifsClient.ConnectAsync(OpenCifsClientCredential credential, CancellationToken)` and `DisconnectAsync(CancellationToken)` as the canonical client lifecycle methods.
- [ ] Decide whether any existing low-level connect/session entry points should remain public but undocumented as happy-path APIs.

### 2. Namespace session and path-first operations

- [ ] Introduce `OpenCifsShareSession` in `src/OpenCIFS.Client` as the primary share-scoped unit of work.
- [ ] Standardize `OpenShareAsync(shareName, CancellationToken)` on the connected client as the primary session-open path.
- [ ] Expose grouped session members with the same shape as OpenNFS: `Files`, `Directories`, `Metadata`, and `Locks`.
- [ ] Add or reshape path-first operations so common usage does not require consumers to manage tree handles or repeat the share name on every call.
- [ ] Preserve advanced connection/session/tree/open APIs as an explicit advanced layer rather than the default happy path.
- [ ] Align parameter ordering and cancellation-token placement with OpenNFS for all comparable operations.

### 3. Result envelopes and exceptions

- [ ] Introduce a typed exception hierarchy for OpenCIFS client and server surfaces.
- [ ] Ensure every typed exception carries both a native SMB/NTSTATUS code and a normalized category such as `NotFound`, `AccessDenied`, `Conflict`, `Unsupported`, `IoError`, or `ProtocolError`.
- [ ] Add a non-throwing result-envelope pattern for operations where protocol detail should be preserved instead of flattened into generic failure.
- [ ] Standardize the naming convention for throwing and non-throwing method pairs with OpenNFS before implementation lands in either repo.
- [ ] Ensure high-level exceptions still retain enough SMB command and context detail for diagnostics.

### 4. Server application alignment

- [ ] Confirm `OpenCifsServerBuilder.BuildApplication()` is the primary server construction path in `src/OpenCIFS.Server`.
- [ ] Confirm `OpenCifsServerApplication` with `StartAsync`, `StopAsync`, and `RunAsync` is the primary documented server host surface.
- [ ] Introduce a clearer `OpenCifsServer` configuration/runtime model if it materially improves parity with OpenNFS builder -> server -> application flow.
- [ ] Refactor backend composition toward one mandatory filesystem contract plus an open-ended set of optional capability contracts and discoverable flags.
- [ ] Keep built-in local filesystem-backed shares as a first-class setup path.

### 5. Advanced surface boundaries

- [ ] Define which namespaces, types, or builder options represent the advanced/raw surface.
- [ ] Make raw connection/session/tree/open workflows discoverable but clearly secondary in quickstarts.
- [ ] Ensure advanced APIs preserve full protocol fidelity and are not simplified into the high-level shape.
- [ ] Document how high-level share-session operations map onto advanced SMB concepts for developers who need to drop down a layer.

### 6. Documentation and samples

- [ ] Update `README.md` so its first client example uses the aligned builder -> client -> share session -> grouped path API flow.
- [ ] Update `README.md` so its first server example uses `OpenCifsServerBuilder.BuildApplication()` and `RunAsync`.
- [ ] Update `OPENCIFS.md` to document the layered model: high-level share-session APIs first, advanced protocol APIs second.
- [ ] Update `docs/coverage-matrix.md` and `docs/interop-matrix.md` where needed so they reference the aligned public surface rather than only lower-level primitives.
- [ ] Add a short "OpenCIFS and OpenNFS usage parity" section to `README.md` or `OPENCIFS.md` so consumers see the intentional convergence.
- [ ] Document credential injection point, exception/result-envelope behavior, and the advanced/raw escape hatches.
- [ ] Update `src/Sample.OpenCifsServer` to use the aligned server application surface.
- [ ] Update client-facing sample code in `src/OpenCIFS.Client.Tests.Console` or a dedicated sample so a consumer can copy one happy-path example without touching low-level primitives.

### 7. Tests and approval gates

- [ ] Add API-shape approval or reflection tests in `src/OpenCIFS.Client.Tests.Xunit`, `src/OpenCIFS.Server.Tests.Xunit`, or shared test projects that validate the aligned public naming:
  - [ ] `OpenCifsClientBuilder`
  - [ ] `OpenCifsClient`
  - [ ] `ConnectAsync` / `DisconnectAsync`
  - [ ] `OpenCifsShareSession`
  - [ ] `Files` / `Directories` / `Metadata` / `Locks`
  - [ ] `OpenCifsServerApplication`
- [ ] Add tests for share-session path-first flows so common operations do not regress back toward tree-handle-centric usage.
- [ ] Add tests for exception mapping and normalized category coverage.
- [ ] Add tests for result-envelope behavior and parity with the OpenNFS naming convention.
- [ ] Add smoke tests that compile and execute the canonical README client and server snippets, or equivalent sample-based verification if snippet tests are not practical.
- [ ] Mirror the same acceptance-test concepts in OpenNFS so both repos can prove parity rather than just claim it.

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
- Throwing APIs and result-envelope APIs exist in parallel, and both repos use the same naming convention for the pair.
- Typed exceptions expose both NTSTATUS and normalized error categories.
- `OpenCifsServerApplication` is the primary server host surface, and the builder/application story matches OpenNFS.
- `README.md`, `OPENCIFS.md`, relevant `docs/` pages, and sample code all show the aligned usage pattern rather than the older low-level-first flow.
- Automated tests enforce API-shape parity, exception mapping expectations, and the canonical usage snippets.
- Advanced/raw APIs still exist and still expose full protocol truth.

## Open questions

- What is the final name for the non-throwing result-envelope method pattern, and can both repos commit to it before implementation begins?
- How much of `OpenCifsClientFacade` should remain public after `OpenCifsClient` and `OpenCifsShareSession` become the primary surface?
- Should the compatibility approval tests live entirely in each repo, or should both repos read a shared manifest later once the shapes stabilize?
- Which optional CIFS server capabilities should get first-class adapter contracts in the initial aligned pass versus later follow-up work?
