namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 negotiate context identifiers.
    /// </summary>
    public enum Smb2NegotiateContextType : ushort
    {
        /// <summary>
        /// Preauthentication integrity capabilities.
        /// </summary>
        PreauthIntegrityCapabilities = 0x0001,

        /// <summary>
        /// Encryption capabilities.
        /// </summary>
        EncryptionCapabilities = 0x0002,

        /// <summary>
        /// Compression capabilities.
        /// </summary>
        CompressionCapabilities = 0x0003,

        /// <summary>
        /// Netname context.
        /// </summary>
        Netname = 0x0005,

        /// <summary>
        /// Transport capabilities.
        /// </summary>
        TransportCapabilities = 0x0006,

        /// <summary>
        /// RDMA transform capabilities.
        /// </summary>
        RdmaTransformCapabilities = 0x0007,

        /// <summary>
        /// Signing capabilities.
        /// </summary>
        SigningCapabilities = 0x0008
    }
}
