namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB signing algorithm identifiers.
    /// </summary>
    public enum SigningAlgorithmId : ushort
    {
        /// <summary>
        /// HMAC-SHA256.
        /// </summary>
        HmacSha256 = 0x0000,

        /// <summary>
        /// AES-CMAC.
        /// </summary>
        AesCmac = 0x0001,

        /// <summary>
        /// AES-GMAC.
        /// </summary>
        AesGmac = 0x0002
    }
}

