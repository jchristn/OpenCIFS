namespace OpenCIFS.Security
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Inputs required to derive SMB 3.x signing and encryption subkeys.
    /// </summary>
    public sealed class SmbKeyDerivationInputs
    {
        /// <summary>
        /// Session key returned by the authentication mechanism.
        /// </summary>
        public byte[] SessionKey
        {
            get
            {
                return _SessionKey;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(SessionKey), "SessionKey cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(SessionKey), "SessionKey must not be empty.");
                }

                _SessionKey = value;
            }
        }

        /// <summary>
        /// Optional full session key used by SMB 3.1.1 AES-256 encryption-key derivation.
        /// </summary>
        public byte[] FullSessionKey
        {
            get
            {
                return _FullSessionKey;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(FullSessionKey), "FullSessionKey cannot be null.");
                }

                _FullSessionKey = value;
            }
        }

        /// <summary>
        /// Negotiated SMB dialect.
        /// </summary>
        public SmbDialect Dialect { get; set; } = SmbDialect.Smb311;

        /// <summary>
        /// Negotiated SMB cipher identifier.
        /// </summary>
        public SmbCipherAlgorithmId CipherAlgorithmId { get; set; } = SmbCipherAlgorithmId.Aes128Gcm;

        /// <summary>
        /// SMB 3.1.1 preauthentication integrity transcript hash.
        /// </summary>
        public byte[] PreauthIntegrityHash
        {
            get
            {
                return _PreauthIntegrityHash;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(PreauthIntegrityHash), "PreauthIntegrityHash cannot be null.");
                }

                _PreauthIntegrityHash = value;
            }
        }

        private byte[] _SessionKey = new byte[] { 0x00 };
        private byte[] _FullSessionKey = Array.Empty<byte>();
        private byte[] _PreauthIntegrityHash = Array.Empty<byte>();
    }
}
