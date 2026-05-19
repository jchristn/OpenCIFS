# OpenCIFS.Security

Shared OpenCIFS security helpers for NTLMv2, SPNEGO, signing, encryption, transcript hashing, and SMB key derivation.

OpenCIFS `0.1.0` is alpha software. This package reflects the bounded security surface currently exercised by OpenCIFS, and exhaustive compatibility testing across SMB dialects, authentication environments, and external peers has not been performed.

## Scope

- NTLMv2 response and MIC helpers
- SPNEGO token handling
- SMB signing and verification helpers
- SMB 3.0.2 AES-128-CCM transform helpers
- preauthentication hashing and negotiated key-derivation helpers

`OpenCIFS.Security` is an advanced dependency package. Most consumers should use it transitively through `OpenCIFS.Client` or `OpenCIFS.Server` instead of taking a direct dependency.

## Install

```powershell
dotnet add package OpenCIFS.Security
```

The verified scope currently matches the managed NTLMv2 and signing flows used by OpenCIFS under SMB 2.0.2 and SMB 2.1 by default, plus the bounded SMB 3.0 / SMB 3.0.2 AES-CMAC signing slice and the bounded SMB 3.0.2 AES-128-CCM encrypted-session slice. Native Kerberos and broader SMB 3.x behavior such as SMB 3.1.1 signing or encryption negotiation remain backlog.
