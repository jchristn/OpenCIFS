namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 header flags2 values.
    /// </summary>
    [Flags]
    public enum Smb1HeaderFlags2 : ushort
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// Long names supported.
        /// </summary>
        LongNames = 0x0001,

        /// <summary>
        /// Extended attributes supported.
        /// </summary>
        ExtendedAttributes = 0x0002,

        /// <summary>
        /// Extended security negotiation.
        /// </summary>
        ExtendedSecurity = 0x0800,

        /// <summary>
        /// DFS operations.
        /// </summary>
        Dfs = 0x1000,

        /// <summary>
        /// NT status codes.
        /// </summary>
        NtStatus = 0x4000,

        /// <summary>
        /// Unicode strings.
        /// </summary>
        Unicode = 0x8000
    }
}

