namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Computes AES-GMAC authentication values.
    /// </summary>
    public static class AesGmac
    {
        private const int SignatureLength = 16;

        /// <summary>
        /// Compute an AES-GMAC value for the supplied authenticated data.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="nonce">Twelve-byte GCM nonce.</param>
        /// <param name="authenticatedData">Authenticated data bytes.</param>
        /// <returns>Sixteen-byte GMAC value.</returns>
        public static byte[] ComputeMac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticatedData)
        {
            byte[] tag = new byte[SignatureLength];

            using AesGcm algorithm = new AesGcm(key.ToArray(), SignatureLength);
            algorithm.Encrypt(nonce, ReadOnlySpan<byte>.Empty, Span<byte>.Empty, tag, authenticatedData);
            return tag;
        }

        /// <summary>
        /// Verify an AES-GMAC value for the supplied authenticated data.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="nonce">Twelve-byte GCM nonce.</param>
        /// <param name="authenticatedData">Authenticated data bytes.</param>
        /// <param name="expectedMac">Expected GMAC value.</param>
        /// <returns><c>true</c> if the GMAC is valid.</returns>
        public static bool Verify(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> authenticatedData, ReadOnlySpan<byte> expectedMac)
        {
            if (expectedMac.Length != SignatureLength)
            {
                return false;
            }

            byte[] actualMac = ComputeMac(key, nonce, authenticatedData);
            return CryptographicOperations.FixedTimeEquals(actualMac, expectedMac);
        }
    }
}
