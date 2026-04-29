namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Wraps the BCL AES-CCM authenticated-encryption primitive.
    /// </summary>
    public static class AesCcmCipher
    {
        /// <summary>
        /// Encrypt and authenticate plaintext bytes with AES-CCM.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="nonce">CCM nonce bytes.</param>
        /// <param name="plaintext">Plaintext bytes.</param>
        /// <param name="associatedData">Associated data bytes.</param>
        /// <param name="tagLength">Authentication-tag length in bytes.</param>
        /// <returns>Ciphertext and authentication tag.</returns>
        public static AeadCipherResult Encrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> associatedData, int tagLength = 16)
        {
            byte[] ciphertext = new byte[plaintext.Length];
            byte[] tag = new byte[tagLength];

            using AesCcm algorithm = new AesCcm(key.ToArray());
            algorithm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
            return new AeadCipherResult(ciphertext, tag);
        }

        /// <summary>
        /// Decrypt and authenticate ciphertext bytes with AES-CCM.
        /// </summary>
        /// <param name="key">AES key bytes.</param>
        /// <param name="nonce">CCM nonce bytes.</param>
        /// <param name="ciphertext">Ciphertext bytes.</param>
        /// <param name="authenticationTag">Authentication-tag bytes.</param>
        /// <param name="associatedData">Associated data bytes.</param>
        /// <returns>Decrypted plaintext bytes.</returns>
        public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> authenticationTag, ReadOnlySpan<byte> associatedData)
        {
            byte[] plaintext = new byte[ciphertext.Length];

            using AesCcm algorithm = new AesCcm(key.ToArray());
            algorithm.Decrypt(nonce, ciphertext, authenticationTag, plaintext, associatedData);
            return plaintext;
        }
    }
}
