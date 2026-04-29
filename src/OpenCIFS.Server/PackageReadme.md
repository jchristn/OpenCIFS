# OpenCIFS.Server

Managed direct-TCP SMB 2.0.2 and SMB 2.1 server surface for OpenCIFS.

## Scope

- direct-TCP listener and authenticated session handling
- share registration and local filesystem-backed share hosting
- bounded file-I/O, metadata, locking, notify, oplock, lease, and durable reconnect handling
- typed request callbacks for authenticated session, tree connect, create, query, set, and IOCTL control

## Install

```powershell
dotnet add package OpenCIFS.Server
```

This package depends on `OpenCIFS.Protocol`, `OpenCIFS.Security`, and `OpenCIFS.Transport`.

## Example

```csharp
using OpenCIFS.Server;

OpenCifsServerOptions options = new OpenCifsServerOptions
{
    ServerName = "demo-server",
    BindAddress = "0.0.0.0",
    BindPort = 4450,
};

OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(options)
    .AddAccount(new OpenCifsServerAccount
    {
        UserName = "alice",
        UserDomain = "WORKGROUP",
        Password = "Password123!",
    })
    .AddFileSystemShare(new OpenCifsServerFileSystemShare
    {
        ShareName = "share",
        RootPath = "C:\\OpenCifsShare",
        CreateRootIfMissing = true,
    });

await using OpenCifsServerApplication server = builder.BuildApplication();
await server.StartAsync();
```

Use `Sample.OpenCifsServer` for the full tester-facing sample host. The verified scope currently covers the managed SMB 2.0.2 and SMB 2.1 slices implemented in this repository; SMB 3.x, SMB1/CIFS, DFS, named pipes, and Kerberos remain backlog.
