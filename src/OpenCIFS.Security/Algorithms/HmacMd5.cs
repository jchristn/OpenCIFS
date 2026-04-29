namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Computes HMAC-MD5 values for NTLMv2 message protection.
    /// </summary>
    public static class HmacMd5
    {
        /// <summary>
        /// Compute an HMAC-MD5 value for the supplied message bytes.
        /// </summary>
        /// <param name="key">HMAC key bytes.</param>
        /// <param name="message">Message bytes.</param>
        /// <returns>Sixteen-byte HMAC-MD5 result.</returns>
        public static byte[] HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> message)
        {
            using HMACMD5 algorithm = new HMACMD5(key.ToArray());
            return algorithm.ComputeHash(message.ToArray());
        }
    }
}
