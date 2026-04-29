# OpenCIFS

OpenCIFS is an MIT-licensed SMB/CIFS library suite for .NET.

Current repository status:

- Milestone 0 bootstrap is in place.
- The solution, project graph, package management, CI entrypoints, coverage matrix, and Touchstone runner matrix are implemented.
- The verified working dialect surface is now managed direct-TCP SMB 2.0.2 and SMB 2.1; SMB 3.x and SMB1/CIFS remain backlog.
- `OpenCIFS.Protocol`, `OpenCIFS.Security`, `OpenCIFS.Transport`, `OpenCIFS.Server`, and `OpenCIFS.Client` now form a packable package graph, each package now emits package-specific readme and metadata content, and a local-feed downstream package-smoke consumer verifies the packaged client/server/protocol flow end to end.
- `eng/run-readme-smoke.ps1` and `eng/run-integration-gates.ps1` now keep the documented consumer surface executable: README smoke compiles a temporary project-reference consumer from the client and server examples below and verifies authenticated echo, directory create, file write or read, metadata query, enumeration, rename, cleanup, callback invocation, and non-empty-directory delete rejection, while the broader integration gate layers that on top of build, Touchstone, framework runners, package smoke, Python real-client, Samba, and native Windows smoke coverage.
- `eng/run-release-gates.ps1` now provides a one-command `Release` validation path for publishability work: it reruns the full integration gate, validates the coverage and interop matrix structure, rejects stale pass-row interop evidence and stale concrete verification dates, and records a release summary in `artifacts/release-gates/release-gates.json`.
- `Sample.OpenCifsServer` exposes a builder-backed managed direct-TCP SMB 2.0.2 and SMB 2.1 sample host with generic local filesystem share-backend registration, typed authenticated-session/tree/create/query/set/IOCTL callback hooks, explicit start/stop lifecycle control, secure defaults, runtime configuration overrides, deterministic tester-facing status output, shared multi-client direct-TCP server state for cross-connection async directory notifications, share-access enforcement, byte-range lock-conflict handling, bounded exclusive oplock-break downgrade handling, bounded SMB 2.1 lease grant and signed lease-break handling, a bounded durable batch-oplock reconnect path with shared persistent and volatile file IDs and preserved byte-range lock state across transport loss, bounded SMB 2.1 `SMB2_GLOBAL_CAP_LARGE_MTU` negotiation plus multi-credit large read or write handling, broader synchronous related-compound handling for metadata, locking, and open-scoped `IOCTL`, plus authenticated SMB2 packet-signing enforcement on the managed path. Local loopback plus bounded Python real-client, Samba-client, and native Windows mapped-drive smoke coverage now verify SMB 2.1 negotiate or authenticate or tree or file-I/O or large-payload transfer or metadata-mutation or rename or delete or watcher-visible nested-create and rename-notify flows, cleanup, and selected negative error paths including unsupported related-compound chains, stale handles, invalid session/tree/open identifiers, signature tampering, and read-only or non-empty delete rejection while lease-v2, external lease-specific interop, long-run soak, and broader SMB 2.1 semantics remain backlog.
- `OpenCIFS.Client` exposes a managed direct-TCP SMB 2.0.2 and SMB 2.1 connection surface for connect, authenticate, tree connect, open, read, write, query, set, enumerate, close, bounded async `CHANGE_NOTIFY`, bounded exclusive `OPLOCK_BREAK` and SMB 2.1 lease-break wait-and-ack handling, bounded SMB 2.1 lease-backed opens, bounded SMB 2.1 multi-credit large read or write requests with automatic credit-window growth, and bounded durable-open reconnect across abrupt transport loss with preserved byte-range lock ownership, plus a stable high-level facade for authenticated echo, directory create, file write, file read, large-payload chunked transfer, directory enumeration, metadata query, bounded basic-info and file-length mutation, rename, file or empty-directory delete, and bounded directory-change waits against verified live-listener OpenCIFS paths and bounded Samba-server smoke. Server-returned SMB failures on that surface now propagate as `OpenCifsStatusException` with the SMB2 command and NTSTATUS instead of collapsing to generic operation failures. Shared positive and negative coverage now also includes authenticated request signing, signed-response validation, missing or tampered-signature rejection, invalid-credit exhaustion, bad message-id rejection, stale handles, bad credentials, invalid session/tree/open identifiers across loopback file-I/O and metadata paths, bounded SMB 2.1 multi-credit header validation and large-payload transfer paths, broader synchronous related-compound tree/create/set-info/query-info/lock/ioctl/close coverage with propagated create-failure handling, non-empty-directory delete rejection, unsupported related-compound chain rejection, cross-session share-access success and conflict rejection, byte-range lock-conflict handling, exclusive oplock-break completion and nongrant behavior, SMB 2.1 lease-break completion and rejection paths, durable reconnect after transport disconnect plus mismatched reconnect rejection, durable byte-range lock carryover across reconnect, rename/delete notify completion, non-recursive nested-create notify cancellation, and acceptance of unsigned interim async `STATUS_PENDING` responses while broader client interop remains backlog.

## Projects

### Product

- `src/OpenCIFS.Protocol`
- `src/OpenCIFS.Transport`
- `src/OpenCIFS.Security`
- `src/OpenCIFS.Server`
- `src/OpenCIFS.Client`
- `src/Sample.OpenCifsServer`

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

Coverage-matrix, interop-matrix, and package-graph validation run as part of the build through `eng/OpenCIFS.Build`.

## Test

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\test.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-touchstone.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-package-smoke.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-readme-smoke.ps1
dotnet test src/OpenCIFS.sln --no-build
powershell -ExecutionPolicy Bypass -File .\eng\run-samba-interop.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-real-client-interop.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-windows-client-interop.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-integration-gates.ps1
powershell -ExecutionPolicy Bypass -File .\eng\run-release-gates.ps1 -Configuration Release
```

`eng/test.ps1` now runs the clean build, Touchstone console suites, `dotnet test`, package smoke, and README smoke as one local managed-path gate.

`eng/run-package-smoke.ps1` packs `OpenCIFS.Protocol`, `OpenCIFS.Security`, `OpenCIFS.Transport`, `OpenCIFS.Client`, and `OpenCIFS.Server` into a temporary local feed, validates the emitted nuspec metadata plus package-specific readme and XML-doc payloads, restores a generated downstream consumer against that feed, and verifies authenticated echo, directory create, file write or read, metadata query, directory enumeration, rename, cleanup, bad-credential rejection, and non-empty-directory delete rejection from packaged artifacts. Evidence is written to `artifacts/package-smoke/package-metadata.json` and `artifacts/package-smoke/package-smoke.json`.

`eng/run-readme-smoke.ps1` compiles a temporary downstream consumer against project references, mirrors the documented client and server code examples below, and verifies authenticated echo, directory create, file write or read, metadata query, enumeration, rename, cleanup, callback invocation, and non-empty-directory delete rejection. Evidence is written to `artifacts/readme-smoke/readme-smoke.json`.

`eng/run-integration-gates.ps1` extends `eng/test.ps1` with the Python real-client, Samba, and native Windows interop smoke harnesses so the broader integration-ready path can be exercised with one command.

`eng/run-release-gates.ps1` reruns the full integration stack in `Release`, then calls `eng/validate-release-artifacts.ps1` to verify current coverage and interop matrix structure, require same-day pass-row interop evidence, and record a release summary in `artifacts/release-gates/release-gates.json`.

## Code Examples

The current client and server surfaces are managed direct-TCP SMB `2.0.2` and SMB `2.1` flows. Use TCP `445` for native SMB endpoints, or TCP `4450` when talking to the sample host locally.

The client and server examples below are executable release artifacts: `eng/run-readme-smoke.ps1` compiles a temporary consumer from these flows and verifies the documented path end to end.

### Client Example

This example connects to a remote CIFS server, authenticates, creates a directory, writes a file, reads it back, queries metadata, enumerates the directory, renames the file, and deletes the test paths.

```csharp
using System;
using System.Text;
using OpenCIFS.Client;

OpenCifsClientOptions options = new OpenCifsClientOptions
{
    ServerName = "fileserver.contoso.local",
    ServerPort = 445
};

OpenCifsClientCredential credential = new OpenCifsClientCredential
{
    UserName = "alice",
    UserDomain = "CONTOSO",
    Password = "Password123!"
};

await using OpenCifsClientFacade client = new OpenCifsClientFacade(options);
await client.ConnectAsync(credential);
await client.EchoAsync();

await client.CreateDirectoryAsync("share", "docs");
await client.WriteAllBytesAsync("share", "docs\\hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS"));

byte[] fileBytes = await client.ReadAllBytesAsync("share", "docs\\hello.txt");
OpenCifsClientFileMetadata metadata = await client.GetMetadataAsync("share", "docs\\hello.txt");
OpenCifsClientDirectoryEntry[] entries = await client.EnumerateDirectoryAsync("share", "docs");

Console.WriteLine(Encoding.UTF8.GetString(fileBytes));
Console.WriteLine($"{metadata.Path}: {metadata.EndOfFile} bytes");

foreach (OpenCifsClientDirectoryEntry entry in entries)
{
    Console.WriteLine($"{entry.FileName}: {entry.EndOfFile} bytes");
}

await client.RenameAsync("share", "docs\\hello.txt", "docs\\hello-renamed.txt");
await client.DeleteAsync("share", "docs\\hello-renamed.txt");
await client.DeleteAsync("share", "docs");
```

If you are connecting to `Sample.OpenCifsServer`, set `ServerName = "127.0.0.1"` and `ServerPort = 4450` unless you have explicitly bound the sample host to `445`.

Server-returned SMB failures on the low-level and facade surfaces now raise `OpenCifsStatusException`, so callers can inspect the exact SMB2 command and NTSTATUS:

```csharp
try
{
    await client.DeleteAsync("share", "docs");
}
catch (OpenCifsStatusException exception)
{
    Console.WriteLine($"{exception.Command} failed with {exception.Status}");
}
```

For the bounded SMB 2.x durable-reconnect slice, use `OpenCifsClientConnection` directly, open with `requestDurableHandle: true`, and reconnect that open with `ReconnectDurableOpenAsync` after abrupt transport loss. The verified scope currently preserves the durable batch-oplock open plus its byte-range lock ownership across the reconnect under negotiated SMB `2.0.2` and SMB `2.1`, but it does not claim broader lease-based SMB 2.1 or SMB 3.x reconnect semantics.

For the bounded SMB `2.1` lease slice, use `OpenCifsClientConnection` directly and pass `requestedOplockLevel: Smb2OplockLevel.Lease`, an SMB `2.1` `requestedLeaseState`, and a stable `leaseKey` when opening a file. The verified scope currently covers lease grant handling plus signed lease-break wait-and-ack completion on the managed path, but it does not claim lease-v2 or external lease-specific interop semantics.

For the bounded SMB `2.1` large-I/O slice, use `OpenCifsClientConnection` directly for large reads or writes, or use `OpenCifsClientFacade.WriteAllBytesAsync` and `ReadAllBytesAsync` for automatic chunking when the negotiated credit window is smaller than the total payload. The verified scope currently covers multi-credit `CreditCharge` handling on the managed client and server path, `SMB2_GLOBAL_CAP_LARGE_MTU` negotiation, and `200000`-byte end-to-end transfers through loopback, Samba, Python real-client, and native Windows smoke flows.

### Server Example

This example starts an OpenCIFS server, registers a local filesystem share, accepts remote CIFS clients, and logs authenticated sessions, tree connects, and create requests through the callback surface. Remote clients then perform reads, writes, directory enumeration, rename, and delete operations against the registered share root.

```csharp
using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using OpenCIFS.Server;

string shareRoot = Path.GetFullPath("./DemoShare");
Directory.CreateDirectory(shareRoot);
await File.WriteAllTextAsync(Path.Combine(shareRoot, "welcome.txt"), "hello from OpenCIFS");

OpenCifsServerOptions options = new OpenCifsServerOptions
{
    ServerName = "demo-server",
    BindAddress = "0.0.0.0",
    BindPort = 4450
};

OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(options)
    .AddAccount(new OpenCifsServerAccount
    {
        UserName = "alice",
        UserDomain = "WORKGROUP",
        Password = "Password123!"
    })
    .AddFileSystemShare(new OpenCifsServerFileSystemShare
    {
        ShareName = "share",
        RootPath = shareRoot,
        CreateRootIfMissing = true
    })
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

await using OpenCifsServerApplication server = builder.BuildApplication(
    exception => Console.Error.WriteLine("[open-cifs-server] " + exception.Message));

using CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationTokenSource.Cancel();
};

await server.StartAsync(cancellationTokenSource.Token);

Console.WriteLine($"Listening on {options.BindAddress}:{options.BindPort}");
Console.WriteLine($@"Share path: \\{options.ServerName}\share");
Console.WriteLine("Press Ctrl+C to stop.");

try
{
    await Task.Delay(Timeout.Infinite, cancellationTokenSource.Token);
}
catch (OperationCanceledException)
{
}

await server.StopAsync();
```

For native Windows mounts, bind to TCP `445`. Windows Explorer and `net use` cannot mount a UNC path on a custom SMB port.

## Sample Utility

Write the default sample configuration:

```powershell
dotnet run --project ./src/Sample.OpenCifsServer -- --write-default-config
```

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

That script writes evidence to `artifacts/real-client-interop`, chooses a free loopback direct-TCP port for the current run, connects with SMB signing required, and verifies directory and nested-directory create, a `200000`-byte large-file transfer through repeated signed real-client operations, file write or flush or read, bounded `FILE_BASIC_INFORMATION` mutation, bounded `FILE_END_OF_FILE_INFORMATION` truncation, file rename and delete, directory rename and delete, nested-directory cleanup, read-only delete rejection, non-empty directory delete rejection, and directory enumeration. The evidence includes the real-client result JSON and the printed effective sample-server configuration.

Run the bounded Samba smoke in both directions:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-samba-interop.ps1
```

That script writes evidence to `artifacts/samba-interop`, including the `OpenCIFS.Client` to Samba result JSON, the Samba client to `Sample.OpenCifsServer` result JSON and log, the printed effective sample-server configuration, and the exact `smbclient` and `smbd` versions used for the run. The harness now requires signing on both the OpenCIFS sample-host path and the Samba server path. The `OpenCIFS.Client` to Samba path verifies nested-directory create, a `200000`-byte multi-credit large-file write or read round trip, write or flush or read, `FILE_STANDARD_INFORMATION` query, bounded last-write mutation, bounded EOF truncation, directory enumeration before and after directory rename, non-empty directory delete rejection, deleted-path reopen rejection, file and directory delete, and bounded lock-conflict rejection. The Samba client to `Sample.OpenCifsServer` path verifies NTLMv2 session setup, `FSCTL_VALIDATE_NEGOTIATE_INFO`, nested-directory create, `put` or `get` of a `200000`-byte large file, rename, directory listing, non-empty directory delete rejection, and cleanup.

Run the bounded native Windows mapped-drive smoke against the sample host:

```powershell
powershell -ExecutionPolicy Bypass -File .\eng\run-windows-client-interop.ps1
```

That script writes evidence to `artifacts/windows-client-interop`, chooses a free loopback direct-TCP port for the current run, mounts the sample share through `New-SmbMapping -TransportType TCP`, now uses the UNC target `\\localhost\share` to stay isolated from existing local `127.0.0.1` admin-share sessions, and verifies directory create, a `200000`-byte large-file write or read plus hash check, file write or read, hidden and read-only attribute mutation, read-only clearing, bounded EOF truncation, non-empty directory delete rejection, directory rename, file delete, cleanup, `FileSystemWatcher` nested-create behavior with and without subtree monitoring, watcher-visible rename delivery, share-access conflict rejection, and byte-range lock-conflict rejection with signing required. The workflow records the Windows client environment, printed effective sample-server configuration, per-step command output, and the final workflow JSON.

## Repository Rules

- Product runtime dependencies remain BCL-only.
- Public packages do not claim unimplemented SMB/CIFS capabilities.
- All public types require XML documentation.
- One class or one enum per file.
- Warnings are treated as errors.
- `docs/coverage-matrix.md` and `docs/interop-matrix.md` are release artifacts.




