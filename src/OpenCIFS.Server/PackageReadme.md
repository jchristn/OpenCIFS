# OpenCIFS.Server

Managed direct-TCP SMB 2.0.2 through bounded SMB 3.0.2 server surface for OpenCIFS.

OpenCIFS `0.1.0` is alpha software. The documented server surface and interop claims are intentionally bounded, and exhaustive compatibility testing across SMB dialects, platforms, and third-party peers has not been performed.

A bounded managed SMB 3.0.2 AES-128-CCM encrypted session slice now exists on the managed path, alongside the bounded non-encrypted SMB 3.0 / SMB 3.0.2 compatibility slice exposed through `WithSmb3EncryptionRequired(false)`.

## Scope

- direct-TCP listener and authenticated session handling
- share registration and local filesystem-backed share hosting
- bounded local `IPC$` / named-pipe hosting with the built-in `srvsvc` share-enumeration/share-info endpoint, the built-in UTF-8 echo endpoint, plus host-provided named-pipe endpoints
- bounded file-I/O, metadata, locking, notify, oplock, lease, and durable reconnect handling, including SMB 3.0.2 non-persistent durable-handle v2 reconnect on the managed path
- typed request callbacks for authenticated session, tree connect, create, query, set, and IOCTL control
- bounded SMB 3.0 / SMB 3.0.2 negotiate, secure-negotiate validation, AES-CMAC signing, and SMB 3.0.2 AES-128-CCM session encryption on the managed path, with `WithSmb3EncryptionRequired(false)` exposing the non-encrypted SMB3 compatibility slice

## Install

```powershell
dotnet add package OpenCIFS.Server
```

This package depends on `OpenCIFS.Protocol`, `OpenCIFS.Security`, and `OpenCIFS.Transport`.

## Example

```csharp
using OpenCIFS.Server;

OpenCifsServerBuilder builder = new OpenCifsServerBuilder()
    .WithServerName("demo-server")
    .WithBindAddress("0.0.0.0")
    .WithBindPort(4450)
    .AddAccount(new OpenCifsServerAccount
    {
        UserName = "alice",
        UserDomain = "WORKGROUP",
        Password = "Password123!",
    })
    .AddShare("share", share => share.UseLocalFileSystem("C:\\OpenCifsShare"));

foreach (OpenCifsServerShareInfo shareInfo in builder.GetAvailableShares())
{
    Console.WriteLine($"{shareInfo.ShareName} -> {shareInfo.RootPath}");
}

OpenCifsServer serverDefinition = builder.Build();
await using OpenCifsServerApplication server = serverDefinition.BuildApplication();
await server.RunAsync();
```

`OpenCifsServerBuilder.BuildSettings()` returns immutable `OpenCifsServerSettings`, and `OpenCifsServerBuilder.Build()` returns a configured `OpenCifsServer` for the primary builder -> server -> application flow. `OpenCifsServerBuilder.GetAvailableShares()`, `OpenCifsServer.GetAvailableShares()`, `OpenCifsServerHostBuilder.GetAvailableShares()`, `OpenCifsServerHost.GetAvailableShares()`, and `OpenCifsServerApplication.GetAvailableShares()` expose immutable server-side share snapshots for local configuration introspection, including the synthetic `IPC$` share when bounded named-pipe endpoints are registered. The managed server path now also supports bounded local `IPC$`/named-pipe hosting with the built-in `srvsvc` share-enumeration/share-info endpoint through `OpenCifsServerBuilder.AddSrvsvcShareEnumerationEndpoint()`, the built-in UTF-8 echo endpoint through `AddUtf8EchoNamedPipeEndpoint()`, plus host-provided named-pipe endpoints through `AddNamedPipeEndpoint(...)`.

Builder/configuration faults on the documented server surface now raise `OpenCifsServerConfigurationException`, and managed application lifecycle faults now raise `OpenCifsServerStateException`.

`OpenCifsServerApplication` now also exposes bounded `TryRunAsync`, `TryStartAsync`, and `TryStopAsync` companions that return `OpenCifsServerResult` when you want non-throwing managed lifecycle control for bind conflicts, double-start attempts, or disposed-lifecycle misuse.

Use `Sample.OpenCifsServer` for the full tester-facing sample host. The verified scope currently covers the managed SMB 2.0.2 and SMB 2.1 slices implemented in this repository plus bounded local `IPC$`/named-pipe hosting with the built-in `srvsvc` share-enumeration/share-info endpoint, the built-in UTF-8 echo endpoint, the bounded SMB 3.0 / SMB 3.0.2 negotiate, secure-negotiate validation, AES-CMAC signing, SMB 3.0.2 AES-128-CCM encrypted-session slice, and bounded SMB 3.0.2 non-persistent durable-handle v2 reconnect on the managed path. Continuous availability, persistent clustered handles, SMB 3.1.1, SMB1/CIFS, DFS, broader named-pipe semantics, and Kerberos remain backlog.
