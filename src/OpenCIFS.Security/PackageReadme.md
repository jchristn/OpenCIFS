# OpenCIFS.Security

Shared OpenCIFS security helpers for NTLMv2, SPNEGO, signing, transcript hashing, and SMB key derivation.

## Scope

- NTLMv2 response and MIC helpers
- SPNEGO token handling
- SMB signing and verification helpers
- preauthentication hashing and negotiated key-derivation helpers

`OpenCIFS.Security` is an advanced dependency package. Most consumers should use it transitively through `OpenCIFS.Client` or `OpenCIFS.Server` instead of taking a direct dependency.

## Install

```powershell
dotnet add package OpenCIFS.Security
```

The verified scope currently matches the managed NTLMv2 and signing flows used by OpenCIFS under SMB 2.0.2 and SMB 2.1. Native Kerberos and SMB 3.x encryption flows remain backlog.
