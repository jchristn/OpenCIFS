namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Wraps the BCL AES-GCM authenticated-encryption primitive.
    /// </summary>
    public static class AesGcmCipher
    {
        /// <summary>
        /// Encrypt and authenticate plaintext bytes with AES-GCM.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="nonce">GCM nonce bytes.</param>
        /// <param name="plaintext">Plaintext bytes.</param>
        /// <param name="associatedData">Associated data bytes.</param>
        /// <param name="tagLength">Authentication-tag length in bytes.</param>
        /// <returns>Ciphertext and authentication tag.</returns>
        public static AeadCipherResult Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, int tagLength = 16)
        {
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[tagLength];

            using AesGcm algorithm = new AesGcm(key.ToArray(), tagLength);
            algorithm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return new AeadCipherResult(ciphertext, tag);
        }

        /// <summary>
        /// Decrypt and authenticate ciphertext bytes with AES-GCM.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="nonce">GCM nonce bytes.</param>
        /// <param name="ciphertext">Ciphertext bytes.</param>
        /// <param name="authenticationTag">Authentication-tag bytes.</param>
        /// <param name="associatedData">Associated data bytes.</param>
        /// <returns>Decrypted plaintext bytes.</returns>
        public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag, ReadOnlySpan<byte> associatedData)
        {
            byte[] plaintext = new byte[ciphertext.Length];

            using AesGcm algorithm = new AesGcm(key.ToArray(), authenticationTag.Length);
            algorithm.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
            return plaintext;
        }
    }
}
