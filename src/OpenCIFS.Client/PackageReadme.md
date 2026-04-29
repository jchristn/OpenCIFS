# OpenCIFS.Client

Managed direct-TCP SMB 2.0.2 and SMB 2.1 client surface for OpenCIFS.

## Scope

- authenticate with NTLMv2 over the managed OpenCIFS direct-TCP path
- tree connect, open, read, write, query, set, enumerate, rename, and delete
- bounded async `CHANGE_NOTIFY`
- bounded durable reconnect, exclusive oplock-break handling, SMB 2.1 lease handling, and large multi-credit I/O

## Install

```powershell
dotnet add package OpenCIFS.Client
```

This package depends on `OpenCIFS.Protocol`, `OpenCIFS.Security`, and `OpenCIFS.Transport`.

## Example

```csharp
using System.Text;
using OpenCIFS.Client;

OpenCifsClientOptions options = new OpenCifsClientOptions
{
    ServerName = "fileserver.contoso.local",
    ServerPort = 445,
};

OpenCifsClientCredential credential = new OpenCifsClientCredential
{
    UserName = "alice",
    UserDomain = "CONTOSO",
    Password = "Password123!",
};

await using OpenCifsClientFacade client = new OpenCifsClientFacade(options);
await client.ConnectAsync(credential);
await client.WriteAllBytesAsync("share", "docs\\hello.txt", Encoding.UTF8.GetBytes("hello from OpenCIFS"));
byte[] fileBytes = await client.ReadAllBytesAsync("share", "docs\\hello.txt");
```

Use `OpenCifsClientConnection` directly for the lower-level durable reconnect, lease-backed open, and large multi-credit I/O slices. SMB 3.x, Kerberos, and broader Windows-server interop remain backlog.
