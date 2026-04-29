namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB 3.x encryption cipher identifiers.
    /// </summary>
    public enum SmbCipherAlgorithmId : ushort
    {
        /// <summary>
        /// AES-128-CCM.
        /// </summary>
        Aes128Ccm = 0x0001,

        /// <summary>
        /// AES-128-GCM.
        /// </summary>
        Aes128Gcm = 0x0002,

        /// <summary>
        /// AES-256-CCM.
        /// </summary>
        Aes256Ccm = 0x0003,

        /// <summary>
        /// AES-256-GCM.
        /// </summary>
        Aes256Gcm = 0x0004
    }
}
