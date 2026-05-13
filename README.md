# OpenCIFS

OpenCIFS is an MIT-licensed SMB/CIFS library suite for .NET.

Current repository status:

- Milestone 0 bootstrap is in place.
- The solution, project graph, package management, CI entrypoints, coverage matrix, and Touchstone runner matrix are implemented.
- The verified managed dialect surface now covers direct-TCP SMB 2.0.2, SMB 2.1, a bounded SMB 3.0 / SMB 3.0.2 slice, and a bounded SMB 3.1.1 opt-in preview slice. By default the current managed client and server path prefer encryption-capable SMB 3.0.2 when the peer supports it; `WithPreferredEncryption(false)` plus `WithSmb3EncryptionRequired(false)` expose the bounded non-encrypted SMB3 compatibility slice, and bounded managed SMB 3.0 / SMB 3.0.2 secure-negotiate validation plus non-persistent durable-handle v2 reconnect now runs on the direct-TCP path. The bounded SMB 3.1.1 opt-in preview is reachable through `OpenCifsClientBuilder.WithSmb311Preview()` and `OpenCifsServerBuilder.WithSmb311Preview()`, or through `Sample.OpenCifsServer --enable-smb311-preview true`; when both sides opt in the negotiated dialect lifts to `Smb311` with SHA-512 preauth integrity transcript hashing, AES-GMAC per-message signing, AES-128-GCM session encryption, and full session-setup transcript carry-through into the SMB 3.1.1 key-derivation context. AES-256-GCM/CCM ciphers (gated on Kerberos session keys) remain backlog. SMB1/CIFS codec and bootstrap work exists, but real SMB1 peer interoperability is intentionally outside the current release-gated claim scope.
- `OpenCIFS.Protocol`, `OpenCIFS.Security`, `OpenCIFS.Transport`, `OpenCIFS.Server`, and `OpenCIFS.Client` now form a packable package graph, each package now emits package-specific readme and metadata content, build-time package-claim validation now rejects overbroad nuspec descriptions or package-readme scope claims, and a local-feed downstream package-smoke consumer verifies the packaged client/server/protocol flow end to end.
- `eng/run-readme-smoke.ps1` and `eng/run-integration-gates.ps1` now keep the documented consumer surface executable: README smoke compiles a temporary project-reference consumer from the client and server examples below and verifies authenticated echo, directory create, file write or read, metadata query, enumeration, rename, cleanup, callback invocation, and non-empty-directory delete rejection, while the broader integration gate layers that on top of build, Touchstone, framework runners, package smoke, published-sample smoke, and external Python real-client, Samba, and native Windows smoke coverage replayed under three merged dialect milestones: SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2.
- `OpenCIFS.TestClient` and `OpenCIFS.TestServer` now provide menu-driven manual exercise surfaces on top of the current public client and server APIs. `OpenCIFS.TestClient` can configure the remote endpoint and credentials, browse remote shares through OpenCIFS when the target server exposes `IPC$` and `srvsvc`, inspect bounded remote share details through the same library-backed `srvsvc` path, transceive UTF-8 payloads through bounded named pipes under `IPC$`, open a share, traverse directories, enumerate, review metadata, read or write or rename or delete files, and download or upload test content. `OpenCIFS.TestServer` can configure bind and credential settings, uses a temporary backing directory by default, starts a managed OpenCIFS listener that other clients can connect to without code edits, and registers the bounded built-in `srvsvc` share-enumeration/share-info endpoint plus a bounded UTF-8 echo endpoint so `shares`, `shareinfo`, and `pipe opencifs.echo ...` work end to end through OpenCIFS against the local test server as well. `eng/run-test-console-smoke.ps1` now drives both consoles through redirected stdin and verifies that bounded end-to-end flow.
- `eng/run-nightly-interop.ps1` now provides a deeper current-dialect interop harness: it reruns the Python real-client, Samba, and native Windows three-dialect matrices across SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2 with a larger bounded payload and then composes that with a stronger SMB 2.1 soak for durable reconnect, exclusive oplock-break, lease-break, and large-I/O churn. The resulting nightly artifact is written to `artifacts/nightly-interop/nightly-interop.json`. External durable-handle v2 interop coverage, SMB 3.1.1 negotiation, and broader SMB 3.x nightly coverage remain backlog.
- `OpenCIFS.Core.Tests.Console` and `OpenCIFS.Server.Tests.Console` now include deterministic parser-mutation coverage for representative frame and request readers plus malformed direct-TCP listener bursts, and the current managed-path listener normalizes malformed top-level request traffic into bounded protocol exceptions without taking down later healthy negotiate flows.
- `eng/run-release-gates.ps1` now provides a one-command `Release` validation path for publishability work: it reruns the full integration gate, runs a bounded SMB 2.1 soak over connection churn plus durable reconnect plus `200000`-byte large-I/O round trips, validates the coverage and interop matrix structure, runs a source audit across product and release-facing surfaces, rejects stale pass-row interop evidence and stale concrete verification dates, and records a release summary in `artifacts/release-gates/release-gates.json`.
- `Sample.OpenCifsServer` exposes a builder-backed managed direct-TCP SMB 2.0.2, SMB 2.1, and bounded SMB 3.0.2 sample host with a clearer `OpenCifsServerBuilder -> OpenCifsServer -> OpenCifsServerApplication` construction path, immutable `OpenCifsServerSettings`, generic local filesystem share-backend registration, public share-introspection snapshots through `GetAvailableShares()`, typed authenticated-session/tree/create/query/set/IOCTL callback hooks, explicit start/stop lifecycle control, secure defaults, runtime configuration overrides, deterministic tester-facing status output, shared multi-client direct-TCP server state for cross-connection async directory notifications, share-access enforcement, byte-range lock-conflict handling, bounded exclusive oplock-break downgrade handling, bounded SMB 2.1 lease grant and signed lease-break handling, a bounded durable reconnect path for batch-oplock and lease-backed opens with shared persistent and volatile file IDs plus preserved byte-range lock state across transport loss, bounded SMB 2.1 `SMB2_GLOBAL_CAP_LARGE_MTU` negotiation plus multi-credit large read or write handling, broader synchronous related-compound handling for metadata, locking, and open-scoped `IOCTL`, bounded SMB 3.0 / SMB 3.0.2 secure-negotiate validation plus AES-CMAC signing, and bounded SMB 3.0.2 AES-128-CCM session encryption with encrypted file-I/O, realistic compounding, and non-persistent durable-handle v2 batch reconnect coverage on the managed path. Local loopback plus bounded published-sample, Python real-client, Samba-client, native Windows mapped-drive smoke, and the timed `Release` soak now verify the claimed SMB 2.0.2, SMB 2.1, and bounded SMB 3.0.2 negotiate or authenticate or tree or file-I/O or large-payload transfer or metadata-mutation or rename or delete or watcher-visible nested-create and rename-notify flows, cleanup, and selected negative error paths including unsupported related-compound chains, stale handles, invalid session/tree/open identifiers, signature tampering, encrypted-packet tampering, read-only or non-empty delete rejection, detached durable lock conflicts, exclusive oplock-break completion, lease-backed reconnect rejection for missing or mismatched lease state, lease-break completion, post-reconnect recovery, non-persistent durable-handle v2 reconnect recovery, and secure-negotiate mismatch rejection while lease-v2 and broader external SMB 3.x behavior remain backlog.
- `OpenCIFS.Client` now exposes an aligned primary surface through `OpenCifsClientBuilder`, `OpenCifsClient`, and `OpenCifsShareSession`, with grouped path-first `Files`, `Directories`, `Metadata`, and `Locks` APIs for the common consumer journey. The primary surface now also has bounded non-throwing `Try...Async` companions that return `OpenCifsClientResult` / `OpenCifsClientResult<T>` so integrations can preserve SMB command, NTSTATUS, normalized category, and typed client-exception detail without relying on exceptions for expected negative paths. When the remote server exposes `IPC$` and `srvsvc`, the primary surface also supports bounded remote share browsing through `OpenCifsClient.EnumerateSharesAsync(...)` / `TryEnumerateSharesAsync(...)`, bounded remote share inspection through `OpenCifsClient.GetShareInfoAsync(...)` / `TryGetShareInfoAsync(...)`, and bounded generic named-pipe traffic through `OpenCifsClient.TransceiveNamedPipeAsync(...)` / `TryTransceiveNamedPipeAsync(...)`. By default the builder surface prefers encryption-capable SMB 3.0.2 when the peer supports it, and `OpenCifsClientBuilder.WithPreferredEncryption(false)` exposes the bounded non-encrypted SMB 3.0 / SMB 3.0.2 compatibility slice when the server likewise relaxes `RequireEncryptionForSmb3`. The advanced/raw surface remains available through `OpenCifsClientConnection` for direct tree/open/session flows, bounded async `CHANGE_NOTIFY`, bounded exclusive `OPLOCK_BREAK` and SMB 2.1 lease-break wait-and-ack handling, bounded SMB 2.1 lease-backed opens, bounded SMB 2.1 multi-credit large read or write requests with automatic credit-window growth, bounded realistic related `create -> query -> close`, `open -> read -> close`, and `create -> write -> flush -> close` helpers, bounded durable-open reconnect across abrupt transport loss with preserved byte-range lock ownership plus SMB 2.1 lease-backed reconnect state and bounded SMB 3.0.2 non-persistent durable-handle v2 reconnect state, bounded AES-128-CCM encrypted request/response wrapping after SMB 3.0.2 session setup, bounded SMB 3.0 / SMB 3.0.2 secure-negotiate validation on the direct-TCP path, bounded remote share browsing through `OpenCifsClientConnection.EnumerateRemoteSharesAsync(...)` / `TryEnumerateRemoteSharesAsync(...)`, bounded remote share inspection through `OpenCifsClientConnection.GetRemoteShareInfoAsync(...)` / `TryGetRemoteShareInfoAsync(...)`, bounded generic named-pipe traffic through `OpenCifsClientConnection.TransceiveNamedPipeAsync(...)` / `TryTransceiveNamedPipeAsync(...)`, and bounded advanced/raw `Try...Async` companions for lifecycle, compound, open, I/O, query, set, notify, close, and disconnect flows. Server-returned SMB failures on both layers propagate as `OpenCifsStatusException` with the SMB2 command, NTSTATUS, and normalized `OpenCifsErrorCategory`, bounded RPC service failures now propagate as `OpenCifsClientRpcException` with the service name, operation name, service return code, and normalized category, and local lifecycle misuse or malformed managed-protocol behavior on the documented client surfaces now raise `OpenCifsClientStateException` and `OpenCifsClientProtocolException` instead of collapsing to generic operation failures. Shared positive and negative coverage now also includes authenticated request signing, signed-response validation, missing or tampered-signature rejection, invalid-credit exhaustion, bad message-id rejection, stale handles, bad credentials, invalid session/tree/open identifiers across loopback file-I/O and metadata paths, bounded SMB 2.1 multi-credit header validation and large-payload transfer paths, broader synchronous related-compound tree/create/set-info/query-info/lock/ioctl/close coverage with propagated create-failure handling, realistic direct-TCP related `open -> read -> close`, `create -> query -> close`, and `create -> write -> flush -> close` helper coverage, non-empty-directory delete rejection, unsupported related-compound chain rejection, cross-session share-access success and conflict rejection, byte-range lock-conflict handling, exclusive oplock-break completion and nongrant behavior, SMB 2.1 lease-break completion and rejection paths, batch-backed and lease-backed durable reconnect after transport disconnect plus mismatched reconnect rejection, durable byte-range lock carryover across reconnect, reconnect-time lease downgrade when a competing open exists, rename/delete notify completion, non-recursive nested-create notify cancellation, acceptance of unsigned interim async `STATUS_PENDING` responses, secure-negotiate request/response matching and mismatch rejection on the SMB3 managed path, the bounded advanced/raw result-envelope path, the bounded primary-surface result-envelope path, the bounded SRVSVC share-browsing/share-info path, the bounded generic named-pipe transceive path, and the bounded managed SMB 3.0 / SMB 3.0.2 negotiate plus AES-CMAC signing and SMB 3.0.2 AES-128-CCM encryption slice while lease-v2, broader Windows-server interop, AES-256 ciphers (gated on Kerberos), and external SMB 3.1.1 interop with Windows / Samba clients remain backlog.

## Projects

### Product

- `src/OpenCIFS.Protocol`
- `src/OpenCIFS.Transport`
- `src/OpenCIFS.Security`
- `src/OpenCIFS.Server`
- `src/OpenCIFS.Client`
- `src/Sample.OpenCifsServer`

### Manual Utilities

- `src/OpenCIFS.TestClient`
- `src/OpenCIFS.TestServer`

### Test

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

## Build

```powershell
dotnet restore src/OpenCIFS.sln
dotnet build src/OpenCIFS.sln
```

Coverage-matrix, interop-matrix, package-graph, package-claim, and source-audit validation run as part of the build through `eng/OpenCIFS.Build`.

## Test

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\test.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-touchstone.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-package-smoke.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-readme-smoke.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-test-console-smoke.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-soak-smoke.ps1 -Configuration Release
dotnet test src/OpenCIFS.sln --no-build
powershell -ExecutionPolicy Bypass -File .\eng\run-samba-interop.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-real-client-interop.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-windows-client-interop.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-nightly-interop.ps1 -Configuration Release
powershell -ExecutionPolicy Bypass -File .\eng\run-integration-gates.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-release-gates.ps1 -Configuration Release
```

`eng/test.ps1` now runs the clean build, Touchstone console suites, `dotnet test`, package smoke, README smoke, and tester-console smoke as one local managed-path gate.

The Touchstone core and server suites now also include deterministic parser-mutation corpuses and malformed direct-TCP listener bursts, so malformed-input hardening is exercised on every local managed-path gate run before the broader external interop stack is replayed.

`eng/run-package-smoke.ps1` packs `OpenCIFS.Protocol`, `OpenCIFS.Security`, `OpenCIFS.Transport`, `OpenCIFS.Client`, and `OpenCIFS.Server` into a temporary local feed, validates the emitted nuspec metadata plus bounded package-specific readme and XML-doc payloads, restores a generated downstream consumer against that feed, and verifies authenticated echo, directory create, file write or read, metadata query, directory enumeration, rename, cleanup, bad-credential rejection, and non-empty-directory delete rejection from packaged artifacts. Evidence is written to `artifacts/package-smoke/package-metadata.json` and `artifacts/package-smoke/package-smoke.json`.

`eng/run-readme-smoke.ps1` compiles a temporary downstream consumer against project references, mirrors the documented client and server code examples below, and verifies authenticated echo, directory create, file write or read, metadata query, enumeration, rename, cleanup, callback invocation, and non-empty-directory delete rejection. Evidence is written to `artifacts/readme-smoke/readme-smoke.json`.

`eng/run-test-console-smoke.ps1` drives `OpenCIFS.TestServer` and `OpenCIFS.TestClient` through redirected stdin, verifies a bounded end-to-end flow over a temporary backing share, and records the resulting stdout/stderr/download artifacts in `artifacts/test-console-smoke/test-console-smoke.json`.

`eng/run-soak-smoke.ps1` compiles a temporary project-reference consumer, starts an in-process SMB 2.1 `OpenCIFS.Server`, and runs a timed operational soak over parallel primary-client connection churn plus large-file round trips and advanced durable or exclusive-oplock or lease churn. The harness verifies repeated share-session directory create or enumerate or rename or cleanup flows, non-empty-directory delete rejection, `200000`-byte payload hashing, detached durable read or lock conflict rejection, durable reconnect success, post-reconnect competing lock recovery, repeated exclusive oplock-break completion, repeated lease-break completion, and the configured minimum soak duration before the artifact is accepted. Evidence is written to `artifacts/soak-smoke/soak-smoke.json`.

`eng/run-integration-gates.ps1` extends `eng/test.ps1` with the Python real-client, Samba, and native Windows interop smoke harnesses, and it now reruns that external stack under three merged dialect milestones: SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2.

`eng/run-nightly-interop.ps1` extends the external-client stack into a deeper current-dialect nightly-style pass. It reruns the Python real-client, Samba, and native Windows three-dialect matrices across SMB 2.0.2, SMB 2.1, and encryption-required SMB 3.0.2 with a larger bounded payload, then composes those artifacts with a stronger SMB 2.1 soak that exercises durable reconnect, exclusive oplock breaks, lease breaks, and large-I/O churn on the managed path. Evidence is written to `artifacts/nightly-interop/nightly-interop.json`. Durable-handle v2, SMB 3.1.1 negotiation, and broader SMB 3.x nightly coverage remain backlog.

`eng/run-release-gates.ps1` reruns the full integration stack in `Release`, including the external SMB 2.0.2, SMB 2.1, and SMB 3.0.2 interop matrix, then runs `eng/run-soak-smoke.ps1`, then calls `eng/validate-release-artifacts.ps1` to verify current coverage and interop matrix structure, rerun the bounded package-claim and source-audit gates, require same-day pass-row interop evidence, validate the timed soak artifact shape and churn counters, require all claimed dialect runs in the external interop artifacts, and record a release summary in `artifacts/release-gates/release-gates.json`.

## Code Examples

The default documented client and server surfaces are managed direct-TCP SMB `2.0.2` through bounded SMB `3.0.2` flows. By default the builders prefer encryption-capable SMB `3.0.2` when the peer supports it; `WithPreferredEncryption(false)` and `WithSmb3EncryptionRequired(false)` expose the bounded non-encrypted SMB3 compatibility slice, and bounded managed SMB `3.0` / `3.0.2` secure-negotiate validation now runs on the direct-TCP path. A bounded SMB `3.1.1` opt-in preview slice is reachable through `OpenCifsClientBuilder.WithSmb311Preview()` and `OpenCifsServerBuilder.WithSmb311Preview()`; when both sides opt in, the negotiated dialect lifts to `Smb311` with SHA-512 preauth integrity, AES-GMAC signing, and AES-128-GCM encryption. SMB1/CIFS codec coverage exists, but real SMB1 peers are outside the current documented interoperability claim. Use TCP `445` for native SMB endpoints, or TCP `4450` when talking to the sample host locally.

The client and server examples below are executable release artifacts: `eng/run-readme-smoke.ps1` compiles a temporary consumer from these flows and verifies the documented path end to end.

### Client Example

This example connects to a remote CIFS server, authenticates, creates a directory, writes a file, reads it back, queries metadata, enumerates the directory, renames the file, and deletes the test paths.

```csharp
using System;
using System.Text;
using OpenCIFS.Client;

OpenCifsClientCredential credential = new OpenCifsClientCredential
{
    UserName = "alice",
    UserDomain = "CONTOSO",
    Password = "Password123!"
};

await using OpenCifsClient client = new OpenCifsClientBuilder()
    .WithServer("fileserver.contoso.local", 445)
    .Build();
await client.ConnectAsync(credential);
await client.EchoAsync();

await using OpenCifsShareSession share = await client.OpenShareAsync("share");
await share.Directories.CreateAsync("/docs");
await share.Files.WriteAllBytesAsync("/docs/hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS"));

byte[] fileBytes = await share.Files.ReadAllBytesAsync("/docs/hello.txt");
OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("/docs/hello.txt");
OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync("/docs");

Console.WriteLine(Encoding.UTF8.GetString(fileBytes));
Console.WriteLine($"{metadata.Path}: {metadata.EndOfFile} bytes");

foreach (OpenCifsClientDirectoryEntry entry in entries)
{
    Console.WriteLine($"{entry.FileName}: {entry.EndOfFile} bytes");
}

await share.Files.RenameAsync("/docs/hello.txt", "/docs/hello-renamed.txt");
await share.Files.DeleteAsync("/docs/hello-renamed.txt");
await share.Directories.DeleteAsync("/docs");
await client.DisconnectAsync();
```

If you are connecting to `Sample.OpenCifsServer`, set `ServerName = "127.0.0.1"` and `ServerPort = 4450` unless you have explicitly bound the sample host to `445`.

Server-returned SMB failures on the high-level and advanced client surfaces now raise `OpenCifsStatusException`, so callers can inspect the exact SMB2 command, NTSTATUS, and normalized category:

```csharp
try
{
    await share.Directories.DeleteAsync("/docs");
}
catch (OpenCifsStatusException exception)
{
    Console.WriteLine($"{exception.Command} failed with {exception.Status} ({exception.Category})");
}
```

Local lifecycle misuse and malformed managed-protocol behavior on the documented client surfaces now raise `OpenCifsClientStateException` and `OpenCifsClientProtocolException` respectively. On the server side, builder/configuration faults and managed application lifecycle faults raise `OpenCifsServerConfigurationException` and `OpenCifsServerStateException`.

If you prefer a non-throwing integration style on the primary client surface, use the bounded `Try...Async` companions. They preserve typed client failures, SMB2 command, NTSTATUS, and normalized categories in `OpenCifsClientResult` / `OpenCifsClientResult<T>` while still letting local argument-validation and cancellation errors throw:

```csharp
OpenCifsClientResult connectResult = await client.TryConnectAsync(credential);
if (!connectResult.IsSuccess)
{
    Console.WriteLine(connectResult.ErrorCategory);
    connectResult.EnsureSuccess();
}

OpenCifsClientResult<OpenCifsShareSession> shareResult = await client.TryOpenShareAsync("share");
await using OpenCifsShareSession share = shareResult.GetValueOrThrow();

OpenCifsClientResult<byte[]> readResult = await share.Files.TryReadAllBytesAsync("/docs/hello.txt");
if (readResult.IsSuccess)
{
    Console.WriteLine(Encoding.UTF8.GetString(readResult.GetValueOrThrow()));
}
else if (readResult.Status == OpenCIFS.Protocol.NtStatus.ObjectNameNotFound)
{
    Console.WriteLine("The file does not exist.");
}
```

The bounded advanced/raw `OpenCifsClientConnection` surface now follows the same naming convention. Use `TryConnectAsync`, `TryConnectAndAuthenticateAsync`, `TryTreeConnectAsync`, `TryOpenAsync`, `TryReadAsync`, `TryWriteAsync`, `TryQueryInfoAsync`, `TryQueryDirectoryAsync`, `TryChangeNotifyAsync`, `TryCompoundOpenReadCloseAsync`, `TryCloseAsync`, and `TryDisconnectAsync` when you want the protocol-exact layer without exception-driven control flow for expected SMB failures. These advanced/raw companions return the same `OpenCifsClientResult` / `OpenCifsClientResult<T>` envelopes and still preserve local argument-validation and cancellation throws.

For the bounded SMB durable-reconnect slice, use `OpenCifsClientConnection` directly, open with `requestDurableHandle: true`, and reconnect that open with `ReconnectDurableOpenAsync` after abrupt transport loss. The verified scope currently preserves durable batch-oplock reconnect plus byte-range lock ownership across the reconnect under negotiated SMB `2.0.2` and SMB `2.1`, covers bounded SMB `2.1` lease-backed durable reconnect when the same SMB client GUID reconnects with the original lease key, and now also covers bounded SMB `3.0.2` non-persistent durable-handle v2 reconnect for the managed batch-oplock path. Broader lease-v2, clustered continuous availability, persistent handles, multichannel, and SMB `3.1.1` reconnect semantics remain backlog (the bounded SMB 3.1.1 opt-in preview covers the negotiate + session-setup + signing + encryption surface but not durable reconnect).

For the bounded SMB `2.1` lease slice, use `OpenCifsClientConnection` directly and pass `requestedOplockLevel: Smb2OplockLevel.Lease`, an SMB `2.1` `requestedLeaseState`, and a stable `leaseKey` when opening a file. The verified scope currently covers lease grant handling plus signed lease-break wait-and-ack completion on the managed path, but it does not claim lease-v2 or external lease-specific interop semantics.

For the bounded SMB `2.1` large-I/O slice, use `OpenCifsClientConnection` directly for explicit large reads or writes, or use `OpenCifsShareSession.Files.WriteAllBytesAsync` and `ReadAllBytesAsync` for automatic chunking when the negotiated credit window is smaller than the total payload. The verified scope currently covers multi-credit `CreditCharge` handling on the managed client and server path, `SMB2_GLOBAL_CAP_LARGE_MTU` negotiation, and `200000`-byte end-to-end transfers through loopback, Samba, Python real-client, native Windows smoke, and the bounded `Release` soak.

For bounded realistic small-flow compounding on the advanced path, use `OpenCifsClientConnection.CompoundCreateQueryInfoCloseAsync(...)`, `CompoundOpenReadCloseAsync(...)`, and `CompoundCreateWriteFlushCloseAsync(...)`. The verified scope currently covers those helpers over managed direct TCP and loopback, including signed related responses and missing-path create-failure propagation, and the high-level `OpenCifsShareSession.Files.ReadAllBytesAsync(...)`, `WriteAllBytesAsync(...)`, and `Metadata.GetAttributesAsync(...)` paths now opportunistically use them when the request fits inside the bounded compound slice.

For the bounded SMB `3.1.1` opt-in preview, set `WithSmb311Preview()` on both the client builder and the server builder. When both sides opt in, the negotiated dialect lifts to `Smb311` end-to-end with SHA-512 preauth integrity transcript hashing, AES-GMAC per-message signing, AES-128-GCM session encryption, and SMB 3.1.1 key derivation using the captured preauth hash. When only the client opts in, the existing tolerance path on the server selects the highest non-3.1.1 dialect (typically SMB 3.0.2), so opting in on the client is safe against legacy servers.

```csharp
using OpenCIFS.Client;
using OpenCIFS.Server;

await using OpenCifsClient client = new OpenCifsClientBuilder()
    .WithServer("fileserver.contoso.local", 445)
    .WithSmb311Preview()
    .Build();
await client.ConnectAsync(credential);

// client.Session.NegotiatedDialect is SmbDialect.Smb311 when the peer also opts in.
```

The bounded SMB 3.1.1 preview is also reachable through `Sample.OpenCifsServer` without code edits using `--enable-smb311-preview true` on the command line; the resulting startup banner reports the SMB 3.1.1 preview state. AES-256-GCM/CCM ciphers (gated on Kerberos session keys) and external SMB 3.1.1 interop with Windows / Samba clients remain backlog.

### Server Example

This example starts an OpenCIFS server, registers a local filesystem share, inspects the shares the server will expose, accepts remote CIFS clients, and logs authenticated sessions, tree connects, and create requests through the callback surface. Remote clients then perform reads, writes, directory enumeration, rename, and delete operations against the registered share root.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Server;

string shareRoot = Path.GetFullPath("./DemoShare");
Directory.CreateDirectory(shareRoot);
await File.WriteAllTextAsync(Path.Combine(shareRoot, "welcome.txt"), "hello from OpenCIFS");

OpenCifsServerBuilder builder = new OpenCifsServerBuilder()
    .WithServerName("demo-server")
    .WithBindAddress("0.0.0.0")
    .WithBindPort(4450)
    .AddAccount(new OpenCifsServerAccount
    {
        UserName = "alice",
        UserDomain = "WORKGROUP",
        Password = "Password123!"
    })
    .AddSrvsvcShareEnumerationEndpoint()
    .AddShare("share", share => share.UseLocalFileSystem(shareRoot))
    .ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
    {
        AuthenticatedSessionCallback = context =>
        {
            Console.WriteLine($"authenticated {context.UserDomain}\\{context.UserName} session={context.SessionId}");
            return null;
        },
        TreeConnectCallback = context =>
        {
            Console.WriteLine($"tree connect share={context.ShareName} root={context.ShareRootPath}");
            return null;
        },
        CreateCallback = context =>
        {
            Console.WriteLine($"create {context.FullPath}");
            return null;
        }
    });

foreach (OpenCifsServerShareInfo shareInfo in builder.GetAvailableShares())
{
    Console.WriteLine($"configured share {shareInfo.ShareName} -> {shareInfo.RootPath}");
}

OpenCifsServer configuredServer = builder.Build();

foreach (OpenCifsServerShareInfo shareInfo in configuredServer.GetAvailableShares())
{
    Console.WriteLine($"server share {shareInfo.ShareName} -> {shareInfo.RootPath}");
}

await using OpenCifsServerApplication server = configuredServer.BuildApplication(
    exception => Console.Error.WriteLine("[open-cifs-server] " + exception.Message));

using CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationTokenSource.Cancel();
};

await server.StartAsync(cancellationTokenSource.Token);

Console.WriteLine($"Listening on {configuredServer.Settings.BindAddress}:{configuredServer.Settings.BindPort}");
Console.WriteLine($@"Share path: \\{configuredServer.Settings.ServerName}\share");
Console.WriteLine("Press Ctrl+C to stop.");

await server.RunAsync(cancellationTokenSource.Token);
```

`OpenCifsServerBuilder.BuildSettings()` now returns immutable `OpenCifsServerSettings`, and `OpenCifsServerBuilder.Build()` now returns an immutable configured `OpenCifsServer` that can build managed applications or advanced listeners later. `OpenCifsServerBuilder.GetAvailableShares()`, `OpenCifsServer.GetAvailableShares()`, `OpenCifsServerHostBuilder.GetAvailableShares()`, `OpenCifsServerHost.GetAvailableShares()`, and `OpenCifsServerApplication.GetAvailableShares()` all return immutable snapshots of the shares that the local OpenCIFS server surface exposes. This is server-side configuration introspection. `OpenCifsServerBuilder.AddSrvsvcShareEnumerationEndpoint()` now enables the bounded built-in `srvsvc` share-enumeration/share-info endpoint over `IPC$`, and `AddNamedPipeEndpoint(...)` lets the host register additional bounded named-pipe endpoints on the managed server path. Separately, `OpenCifsClient.EnumerateSharesAsync(...)`, `OpenCifsClient.GetShareInfoAsync(...)`, `OpenCifsClientConnection.EnumerateRemoteSharesAsync(...)`, and `OpenCifsClientConnection.GetRemoteShareInfoAsync(...)` now provide bounded client-side remote share browsing and share inspection over `IPC$` and `srvsvc` when the target server exposes that path.

If you prefer a non-throwing integration style for managed server lifecycle control, `OpenCifsServerApplication` now also exposes bounded `TryRunAsync`, `TryStartAsync`, and `TryStopAsync` companions that return `OpenCifsServerResult`. Those envelopes preserve typed `OpenCifsServerStateException` failures for bind conflicts, double-start attempts, and disposed-lifecycle misuse while leaving local cancellation behavior throwing:

```csharp
OpenCifsServerResult startResult = await server.TryStartAsync(cancellationTokenSource.Token);
if (!startResult.IsSuccess)
{
    startResult.EnsureSuccess();
}
```

For native Windows mounts, bind to TCP `445`. Windows Explorer and `net use` cannot mount a UNC path on a custom SMB port.

### OpenCIFS And OpenNFS Usage Parity

The primary OpenCIFS happy path now intentionally mirrors the OpenNFS consumer shape:

- build immutable settings through a builder
- create the client
- connect with credentials
- open a protocol-named namespace session
- use grouped path-first APIs
- disconnect explicitly

For OpenCIFS, the credential injection point is `OpenCifsClient.ConnectAsync(OpenCifsClientCredential, CancellationToken)`. The advanced/raw escape hatches remain available through `OpenCifsClientConnection`, `OpenCifsClientSession`, tracked tree/open handles, and the server-side callback or backend contracts when you need SMB-exact behavior beyond the primary builder -> client -> share-session flow.

The current non-throwing pair naming convention for the primary client happy path, the bounded advanced/raw `OpenCifsClientConnection` surface, and the bounded managed `OpenCifsServerApplication` lifecycle surface is `Try...Async`, returning `OpenCifsClientResult` / `OpenCifsClientResult<T>` or `OpenCifsServerResult` as appropriate. That naming is now the documented compatibility target for the later OpenNFS parity pass.

### High-Level And Advanced Surfaces

Use the high-level surface for normal integration work:

- `OpenCifsClientBuilder` builds immutable `OpenCifsClientSettings`.
- `OpenCifsClient` owns connect, disconnect, echo, and `OpenShareAsync(...)`.
- `OpenCifsShareSession` owns grouped path-first `Files`, `Directories`, `Metadata`, and `Locks` operations.
- `OpenCifsServerBuilder` builds immutable `OpenCifsServerSettings` and a configured `OpenCifsServer`.
- `OpenCifsServer` owns the primary builder -> server -> application handoff before `OpenCifsServerApplication` takes over managed listener lifecycle control.

Use the advanced/raw surface when you need protocol-exact SMB control:

- `OpenCifsClientConnection` for explicit connect/authenticate/tree/open/read/write/query/set/notify/lock/oplock/lease/durable-reconnect flows.
- `OpenCifsClientConnection` also exposes bounded `Try...Async` companions across those direct tree/open/session flows when you want protocol-exact operations without exception-driven control flow for expected SMB failures.
- `OpenCifsClientConnection` also exposes bounded realistic compound helpers for `create -> query -> close`, `open -> read -> close`, and `create -> write -> flush -> close` when you need protocol-exact small SMB chains without assembling packets by hand.
- `OpenCifsClientSession` for lower-level request or response state and negotiated-session details.
- `OpenCifsClientTreeHandle`, `OpenCifsClientOpenHandle`, and `OpenCifsShareSession.AdvancedTreeHandle` or `.AdvancedConnection` when you need direct tree/open lifetime control.
- `OpenCifsServerRequestCallbacks` and `OpenCifsServerShareBackend` when the server host needs application-controlled policy or backend behavior.
- `OpenCifsServerApplication.TryRunAsync(...)`, `TryStartAsync(...)`, and `TryStopAsync(...)` when you want non-throwing managed server lifecycle control on top of the primary builder -> application story.

High-level operations map onto SMB concepts instead of hiding them:

- `OpenCifsClient.OpenShareAsync(...)` performs the underlying tree connect.
- `OpenCifsShareSession.Files` and `.Directories` issue the transient open/read/write/query/close flows for common path-based operations.
- `OpenCifsShareSession.Metadata` wraps bounded `QUERY_INFO` and `SET_INFO`.
- `OpenCifsShareSession.Locks` wraps bounded byte-range `LOCK` and `UNLOCK` flows.

For a dedicated copy-pasteable client sample that stays on the aligned high-level path, see [docs/samples/OpenCifsClientHappyPath.cs](/C:/Code/OpenCIFS/docs/samples/OpenCifsClientHappyPath.cs).

## Manual Tester Consoles

Run the menu-driven temporary-share server console:

```powershell
dotnet run --project ./src/OpenCIFS.TestServer
```

That console uses a temporary backing directory by default, lets you set server name or bind address or bind port or share name or credentials or dialect range, and starts a managed `OpenCifsServerApplication` without code edits. Typical startup commands are:

```text
share public
user tester
password Password123!
start
```

Run the menu-driven client console:

```powershell
dotnet run --project ./src/OpenCIFS.TestClient
```

That console lets you set the remote host or port or credentials or dialect range, browse shares through OpenCIFS, inspect bounded share details through the same library-backed `srvsvc` path, transceive bounded named-pipe payloads through `IPC$`, connect, open a share, traverse directories, enumerate, inspect metadata, upload or download, read or write text files, rename, and delete. Typical commands against the server console above are:

```text
server 127.0.0.1
port 4450
user tester
password Password123!
shares
shareinfo public
pipe opencifs.echo hello-from-open-cifs
connect
open public
ls /
```

`shares [server]` in `OpenCIFS.TestClient` now uses the OpenCIFS client stack to browse remote shares through `IPC$` and `srvsvc` when the target server exposes that endpoint. `shareinfo <share>` now uses the same OpenCIFS client stack to query bounded remote share details through `srvsvc` `NetrShareGetInfo`, and `pipe <name> <text>` now uses the same OpenCIFS client stack to send UTF-8 payloads through a bounded named pipe under `IPC$`. Those paths are now verified both against Samba share browsing/share inspection and against the local `OpenCIFS.TestServer`, which registers the bounded built-in `srvsvc` share-enumeration/share-info endpoint plus the bounded `opencifs.echo` UTF-8 echo endpoint by default so the exercised tester stack stays inside OpenCIFS.

Run the bounded tester-console smoke:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-test-console-smoke.ps1
```

That script starts `OpenCIFS.TestServer`, drives `OpenCIFS.TestClient` through a real share-browse or share-info or named-pipe transceive or connect or open-share or create-directory or write or enumerate or metadata or rename or download or delete flow, and records the resulting console logs and round-trip artifact in `artifacts/test-console-smoke`.

For the release-style same-build managed interop matrix, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-managed-interop.ps1
```

That script runs `OpenCIFS.TestClient` against `OpenCIFS.TestServer` as separate processes across SMB 2.0.2, SMB 2.1, and SMB 3.0.2, then records dialect-specific logs and `artifacts/managed-interop/managed-interop.json`.

To exercise `OpenCIFS.Client` against a real Windows SMB server, provision a writable Windows share and credentials first, then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-windows-server-interop.ps1 -ServerName fileserver -ShareName share -UserName user -Password password -Domain DOMAIN
```

That script writes `artifacts/windows-server-interop/windows-server-interop.json`. It is not part of the default release gate until a stable Windows server environment is available.

## Sample Utility

Write the default sample configuration:

```powershell
dotnet run --project ./src/Sample.OpenCifsServer -- --write-default-config
```

Publish a tester-facing sample bundle with generated launcher scripts and default configuration:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\publish-sample-server.ps1 -Configuration Release
```

That script writes a framework-dependent published bundle to `artifacts/published-sample-server`, generates `publish\run-sample-server.ps1`, `publish\print-sample-server-config.ps1`, `publish\validate-sample-server-config.ps1`, writes the default sample configuration, and records the bundle manifest in `artifacts/published-sample-server/sample-server-manifest.json`.

Print the effective configuration, including the direct-TCP endpoint, UNC path, and native-Windows mount guidance:

```powershell
dotnet run --project ./src/Sample.OpenCifsServer -- --print-config
```

Validate a custom local setup without starting the listener:

```powershell
dotnet run --project ./src/Sample.OpenCifsServer -- --validate-config `
  --server-name 127.0.0.1 `
  --bind-address 127.0.0.1 `
  --bind-port 4450 `
  --share-name share `
  --share-path C:\Temp\OpenCifsShare `
  --account-username alice `
  --account-domain WORKGROUP `
  --account-password Password123!
```

Bind the sample host to TCP `445` for native Windows mounting:

```powershell
dotnet run --project ./src/Sample.OpenCifsServer -- `
  --bind-address 0.0.0.0 `
  --bind-port 445
```

Windows Explorer and `net use` cannot target custom SMB ports in UNC paths, so the default `4450` endpoint is for direct-TCP test clients and scripted smoke runs.

Run the bounded real-client smoke against the sample host with runtime overrides:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-real-client-interop.ps1
```

That script writes evidence to `artifacts/real-client-interop`, chooses a free loopback direct-TCP port for each run, pins the sample host and Python client to SMB 2.0.2 and SMB 2.1 in sequence with signing required, and verifies directory and nested-directory create, a `200000`-byte large-file transfer through repeated signed real-client operations, file write or flush or read, bounded `FILE_BASIC_INFORMATION` mutation, bounded `FILE_END_OF_FILE_INFORMATION` truncation, file rename and delete, directory rename and delete, nested-directory cleanup, read-only delete rejection, non-empty directory delete rejection, and directory enumeration. The evidence includes a combined real-client result JSON with per-dialect runs and the printed effective sample-server configuration for both dialects.

Run the published-sample smoke against the bundled executable host:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-published-sample-smoke.ps1
```

That script republishes `Sample.OpenCifsServer`, validates the default generated configuration through the bundled helper scripts, then runs the published executable directly under SMB 2.0.2 and SMB 2.1 with runtime share-path and port overrides so the bundle can be exercised end to end without source edits. Evidence is written to `artifacts/published-sample-smoke`.

Run the bounded Samba smoke in both directions:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-samba-interop.ps1
```

That script writes evidence to `artifacts/samba-interop`, including combined per-dialect `OpenCIFS.Client` to Samba and Samba client to `Sample.OpenCifsServer` result JSON, the combined Samba client log, the printed effective sample-server configuration, and the exact `smbclient` and `smbd` versions used for the run. The harness now requires signing on both the OpenCIFS sample-host path and the Samba server path and reruns both directions under SMB 2.0.2 and SMB 2.1. The `OpenCIFS.Client` to Samba path verifies nested-directory create, a `200000`-byte large-file write or read round trip, write or flush or read, `FILE_STANDARD_INFORMATION` query, bounded last-write mutation, bounded EOF truncation, directory enumeration before and after directory rename, non-empty directory delete rejection, deleted-path reopen rejection, file and directory delete, and bounded lock-conflict rejection. The Samba client to `Sample.OpenCifsServer` path verifies NTLMv2 session setup, `FSCTL_VALIDATE_NEGOTIATE_INFO`, nested-directory create, `put` or `get` of a `200000`-byte large file, rename, directory listing, non-empty directory delete rejection, and cleanup.

To run the same Samba interop flow against multiple checked-in Samba peer image definitions, run:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-samba-peer-matrix.ps1
```

That wrapper currently runs the Bookworm and Trixie Debian-based Samba image definitions and preserves each peer's evidence under `artifacts/samba-peer-matrix`.

To exercise `Sample.OpenCifsServer` through the Linux kernel CIFS client, run the opt-in privileged Docker harness on a host that supports CIFS mounts:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-linux-cifs-interop.ps1
```

That script builds a small Debian `cifs-utils` image, starts `Sample.OpenCifsServer`, mounts the share with `mount.cifs` from a privileged container for SMB 2.0.2, SMB 2.1, and SMB 3.0.2, and writes evidence to `artifacts/linux-cifs-interop`.

Run the bounded native Windows mapped-drive smoke against the sample host:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-windows-client-interop.ps1
```

That script writes evidence to `artifacts/windows-client-interop`, chooses a free loopback direct-TCP port for each run, mounts the sample share through `New-SmbMapping -TransportType TCP`, now uses isolated per-dialect UNC targets on `\\localhost` to stay clear of existing local `127.0.0.1` admin-share sessions and Windows redirector teardown between back-to-back custom-port runs, and reruns the mapped-drive flow under SMB 2.0.2 and SMB 2.1 with signing required. It verifies directory create, a `200000`-byte large-file write or read plus hash check, file write or read, hidden and read-only attribute mutation, read-only clearing, bounded EOF truncation, non-empty directory delete rejection, directory rename, file delete, cleanup, `FileSystemWatcher` nested-create behavior with and without subtree monitoring, watcher-visible rename delivery, share-access conflict rejection, and byte-range lock-conflict rejection. The workflow records the Windows client environment, printed effective sample-server configuration, per-step command output, and the final combined workflow JSON with per-dialect runs.

## Repository Rules

- Product runtime dependencies remain BCL-only.
- Public packages do not claim unimplemented SMB/CIFS capabilities.
- All public types require XML documentation.
- One class or one enum per file.
- Warnings are treated as errors.
- `docs/coverage-matrix.md` and `docs/interop-matrix.md` are release artifacts.




