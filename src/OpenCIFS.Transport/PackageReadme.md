# OpenCIFS.Transport

Shared OpenCIFS transport helpers for direct-TCP SMB framing, NetBIOS session-service framing, and framed connection lifecycle handling.

OpenCIFS `0.1.0` is alpha software. This package reflects the bounded transport surface currently exercised by OpenCIFS, and exhaustive compatibility testing across SMB dialects, platforms, and external peers has not been performed.

## Scope

- direct-TCP frame handling
- NetBIOS session-service frame handling
- bounded connection buffering and lifecycle helpers
- transport primitives used by the managed OpenCIFS client and server surfaces

`OpenCIFS.Transport` is an advanced dependency package. Most consumers should use it transitively through `OpenCIFS.Client` or `OpenCIFS.Server` unless they are building custom protocol hosts on top of the OpenCIFS transport primitives.

## Install

```powershell
dotnet add package OpenCIFS.Transport
```

The verified scope currently covers the transport paths exercised by the managed SMB 2.0.2 and SMB 2.1 client and server flows in this repository.
