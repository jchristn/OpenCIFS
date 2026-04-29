namespace OpenCIFS.Security
{
    using System;

    /// <summary>
    /// NTLMSSP negotiate flags.
    /// </summary>
    [Flags]
    public enum NtlmNegotiateFlags : uint
    {
        /// <summary>
        /// 56-bit session keys are supported.
        /// </summary>
        Key56 = 0x80000000U,

        /// <summary>
        /// The client or server supports key exchange.
        /// </summary>
        KeyExchange = 0x40000000U,

        /// <summary>
        /// 128-bit session keys are supported.
        /// </summary>
        Key128 = 0x20000000U,

        /// <summary>
        /// The version field is present.
        /// </summary>
        Version = 0x02000000U,

        /// <summary>
        /// Target-info AV pairs are present.
        /// </summary>
        TargetInfo = 0x00800000U,

        /// <summary>
        /// Request a non-NT session key.
        /// </summary>
        NonNtSessionKey = 0x00400000U,

        /// <summary>
        /// Identity-level token semantics are requested.
        /// </summary>
        Identity = 0x00100000U,

        /// <summary>
        /// Extended session security is supported.
        /// </summary>
        ExtendedSessionSecurity = 0x00080000U,

        /// <summary>
        /// The target is a share.
        /// </summary>
        TargetTypeShare = 0x00040000U,

        /// <summary>
        /// The target is a server.
        /// </summary>
        TargetTypeServer = 0x00020000U,

        /// <summary>
        /// The target is a domain.
        /// </summary>
        TargetTypeDomain = 0x00010000U,

        /// <summary>
        /// Message signing should always be available.
        /// </summary>
        AlwaysSign = 0x00008000U,

        /// <summary>
        /// The exchange is local to one machine.
        /// </summary>
        LocalCall = 0x00004000U,

        /// <summary>
        /// The workstation field is supplied.
        /// </summary>
        OemWorkstationSupplied = 0x00002000U,

        /// <summary>
        /// The domain field is supplied.
        /// </summary>
        OemDomainNameSupplied = 0x00001000U,

        /// <summary>
        /// Anonymous authentication is requested.
        /// </summary>
        Anonymous = 0x00000800U,

        /// <summary>
        /// NTLM authentication is supported.
        /// </summary>
        Ntlm = 0x00000200U,

        /// <summary>
        /// LM key negotiation is supported.
        /// </summary>
        LmKey = 0x00000080U,

        /// <summary>
        /// Datagram mode is supported.
        /// </summary>
        Datagram = 0x00000040U,

        /// <summary>
        /// Sealing is supported.
        /// </summary>
        Seal = 0x00000020U,

        /// <summary>
        /// Signing is supported.
        /// </summary>
        Sign = 0x00000010U,

        /// <summary>
        /// Request the server target name.
        /// </summary>
        RequestTarget = 0x00000004U,

        /// <summary>
        /// OEM text encoding is supported.
        /// </summary>
        Oem = 0x00000002U,

        /// <summary>
        /// Unicode text encoding is supported.
        /// </summary>
        Unicode = 0x00000001U
    }
}
