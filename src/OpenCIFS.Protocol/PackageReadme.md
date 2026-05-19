# OpenCIFS.Protocol

Shared SMB/CIFS protocol models, enums, codecs, validators, and state types used by the OpenCIFS client and server packages.

OpenCIFS `0.1.0` is alpha software. This package exposes bounded protocol foundations used by the current client and server surfaces, and exhaustive compatibility testing across SMB dialects and external peers has not been performed.

## Scope

- SMB1 and SMB2 frame and header models
- dialect enums and negotiation helpers
- FSCC, metadata, IOCTL, compounding, and state-model types
- validation helpers for bounded OpenCIFS protocol handling

`OpenCIFS.Protocol` is not a standalone SMB client or server. Use `OpenCIFS.Client` or `OpenCIFS.Server` for end-to-end SMB flows.

## Install

```powershell
dotnet add package OpenCIFS.Protocol
```

## Example

```csharp
using OpenCIFS.Protocol;

SmbDialect minimumDialect = SmbDialect.Smb2002;
SmbDialect maximumDialect = SmbDialect.Smb21;

Console.WriteLine($"Dialect floor: {minimumDialect}");
Console.WriteLine($"Dialect ceiling: {maximumDialect}");
```

The verified scope currently covers the managed SMB 2.0.2 and SMB 2.1 slices implemented in this repository. SMB 3.x and SMB1/CIFS compatibility work beyond the current bounded scope remains backlog.
