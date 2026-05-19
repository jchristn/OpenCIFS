# OpenCIFS.Client

Managed direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 client surface for OpenCIFS.

OpenCIFS `0.1.0` is alpha software. The documented client surface and interop claims are intentionally bounded, and exhaustive compatibility testing across SMB dialects, platforms, and third-party peers has not been performed.

A bounded managed SMB 3.0.2 AES-128-CCM encrypted session slice now exists on the managed path, alongside the bounded non-encrypted SMB 3.0 / SMB 3.0.2 compatibility slice exposed through `WithPreferredEncryption(false)`.

## Scope

- authenticate with NTLMv2 over the managed OpenCIFS direct-TCP path
- tree connect, open, read, write, query, set, enumerate, rename, and delete
- bounded remote share browsing and share inspection over `IPC$` and `srvsvc`, plus bounded generic named-pipe transceive over `IPC$`, when the target server exposes those paths
- bounded async `CHANGE_NOTIFY`
- bounded durable reconnect for batch-oplock, SMB 2.1 lease-backed opens, and SMB 3.0.2 non-persistent durable-handle v2 opens, plus exclusive oplock-break handling, SMB 2.1 lease handling, and large multi-credit I/O
- bounded SMB 3.0 / SMB 3.0.2 negotiate, secure-negotiate validation, AES-CMAC signing, and SMB 3.0.2 AES-128-CCM session encryption on the managed path, with `WithPreferredEncryption(false)` exposing the non-encrypted SMB3 compatibility slice

## Install

```powershell
dotnet add package OpenCIFS.Client
```

This package depends on `OpenCIFS.Protocol`, `OpenCIFS.Security`, and `OpenCIFS.Transport`.

## Example

```csharp
using System.Text;
using OpenCIFS.Client;

OpenCifsClientCredential credential = new OpenCifsClientCredential
{
    UserName = "alice",
    UserDomain = "CONTOSO",
    Password = "Password123!",
};

await using OpenCifsClient client = new OpenCifsClientBuilder()
    .WithServer("fileserver.contoso.local", 445)
    .Build();
await client.ConnectAsync(credential);
await using OpenCifsShareSession share = await client.OpenShareAsync("share");
await share.Files.WriteAllBytesAsync("/docs/hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS"));
byte[] fileBytes = await share.Files.ReadAllBytesAsync("/docs/hello.txt");
```

For normal integration work, stay on `OpenCifsClientBuilder` -> `OpenCifsClient` -> `OpenCifsShareSession` and its grouped `Files`, `Directories`, `Metadata`, and `Locks` members. Use `OpenCifsClientConnection`, `OpenCifsClientSession`, tracked tree/open handles, and `OpenCifsShareSession.AdvancedConnection` only when you need protocol-exact SMB control.

When the remote server exposes `IPC$` and `srvsvc`, the primary client surface also supports bounded remote share browsing through `OpenCifsClient.EnumerateSharesAsync(...)` and `TryEnumerateSharesAsync(...)` plus bounded remote share inspection through `OpenCifsClient.GetShareInfoAsync(...)` and `TryGetShareInfoAsync(...)`. The same bounded `IPC$` client path also exposes generic pipe transceive through `OpenCifsClient.TransceiveNamedPipeAsync(...)` and `TryTransceiveNamedPipeAsync(...)`, while the advanced/raw direct-TCP layer exposes matching `OpenCifsClientConnection.EnumerateRemoteSharesAsync(...)` / `TryEnumerateRemoteSharesAsync(...)`, `GetRemoteShareInfoAsync(...)` / `TryGetRemoteShareInfoAsync(...)`, and `TransceiveNamedPipeAsync(...)` / `TryTransceiveNamedPipeAsync(...)` helpers. Those paths are now verified both against Samba share browsing/share inspection and against managed OpenCIFS servers that register `AddSrvsvcShareEnumerationEndpoint()` and `AddUtf8EchoNamedPipeEndpoint()` on the server builder.

Server-returned SMB failures raise `OpenCifsStatusException`, which now exposes the SMB2 command, NTSTATUS, decoded error data, and normalized `OpenCifsErrorCategory`. Bounded RPC-service failures on the documented client surface raise `OpenCifsClientRpcException`, which preserves the service name, operation name, return code, and normalized category. Local lifecycle misuse and malformed managed-protocol behavior on the documented client surfaces now raise `OpenCifsClientStateException` and `OpenCifsClientProtocolException`.

The primary client happy path now also exposes bounded non-throwing `Try...Async` companions that return `OpenCifsClientResult` / `OpenCifsClientResult<T>`. Those envelopes preserve the typed client exception, SMB2 command, NTSTATUS, and normalized category for expected negative paths without forcing consumers to parse exception strings. The bounded advanced/raw `OpenCifsClientConnection` surface now follows the same convention for lifecycle, compound, open, I/O, query, set, notify, close, and disconnect flows.

Use `OpenCifsClientConnection` directly for the lower-level batch-oplock or lease-backed durable reconnect, SMB 3.0.2 non-persistent durable-handle v2 reconnect, lease-backed open, locking, large multi-credit I/O, SMB 3.0.2 encrypted compound flows, and bounded SMB 3.0 / SMB 3.0.2 secure-negotiate validation. SMB 3.1.1, Kerberos, and broader Windows-server interop remain backlog.
