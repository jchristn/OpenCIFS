namespace OpenCIFS.Security
{
    /// <summary>
    /// Holds derived SMB 3.x signing and encryption subkeys.
    /// </summary>
    public sealed class SmbSessionKeySet
    {
        /// <summary>
        /// Initialize the derived key set.
        /// </summary>
        /// <param name="signingKey">Signing-key bytes.</param>
        /// <param name="applicationKey">Application-key bytes.</param>
        /// <param name="encryptionKey">Encryption-key bytes.</param>
        /// <param name="decryptionKey">Decryption-key bytes.</param>
        public SmbSessionKeySet(byte[] signingKey, byte[] applicationKey, byte[] encryptionKey, byte[] decryptionKey)
        {
            SigningKey = Validate(signingKey, nameof(signingKey));
            ApplicationKey = Validate(applicationKey, nameof(applicationKey));
            EncryptionKey = Validate(encryptionKey, nameof(encryptionKey));
            DecryptionKey = Validate(decryptionKey, nameof(decryptionKey));
        }

        /// <summary>
        /// Signing-key bytes.
        /// </summary>
        public byte[] SigningKey { get; }

        /// <summary>
        /// Application-key bytes.
        /// </summary>
        public byte[] ApplicationKey { get; }

        /// <summary>
        /// Encryption-key bytes.
        /// </summary>
        public byte[] EncryptionKey { get; }

        /// <summary>
        /// Decryption-key bytes.
        /// </summary>
        public byte[] DecryptionKey { get; }

        private static byte[] Validate(byte[] value, string parameterName)
        {
            if (value == null)
            {
                throw new ArgumentNullException(parameterName, parameterName + " cannot be null.");
            }

            if (value.Length == 0)
            {
                throw new ArgumentOutOfRangeException(parameterName, parameterName + " must not be empty.");
            }

            return value;
        }
    }
}
