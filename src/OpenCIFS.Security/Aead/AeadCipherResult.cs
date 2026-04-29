namespace OpenCIFS.Security
{
    /// <summary>
    /// Holds authenticated-encryption ciphertext and authentication-tag bytes.
    /// </summary>
    public sealed class AeadCipherResult
    {
        /// <summary>
        /// Initialize the result value.
        /// </summary>
        /// <param name="ciphertext">Ciphertext bytes.</param>
        /// <param name="authenticationTag">Authentication-tag bytes.</param>
        public AeadCipherResult(byte[] ciphertext, byte[] authenticationTag)
        {
            if (ciphertext == null)
            {
                throw new ArgumentNullException(nameof(ciphertext), "Ciphertext cannot be null.");
            }

            if (authenticationTag == null)
            {
                throw new ArgumentNullException(nameof(authenticationTag), "AuthenticationTag cannot be null.");
            }

            Ciphertext = ciphertext;
            AuthenticationTag = authenticationTag;
        }

        /// <summary>
        /// Ciphertext bytes.
        /// </summary>
        public byte[] Ciphertext { get; }

        /// <summary>
        /// Authentication-tag bytes.
        /// </summary>
        public byte[] AuthenticationTag { get; }
    }
}
