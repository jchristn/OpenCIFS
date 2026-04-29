namespace OpenCIFS.Security
{
    using System.Text;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Derives SMB 3.x signing and encryption subkeys from authenticated session material.
    /// </summary>
    public static class SmbSessionKeyDerivation
    {
        /// <summary>
        /// Derive the complete set of SMB 3.x subkeys for a session.
        /// </summary>
        /// <param name="inputs">Dialect, cipher, and session-key inputs.</param>
        /// <param name="keyDerivationProvider">Optional key-derivation provider override.</param>
        /// <returns>Derived key set.</returns>
        public static SmbSessionKeySet DeriveKeys(SmbKeyDerivationInputs inputs, IKeyDerivationProvider? keyDerivationProvider = null)
        {
            if (inputs == null)
            {
                throw new ArgumentNullException(nameof(inputs), "Inputs cannot be null.");
            }

            IKeyDerivationProvider provider = keyDerivationProvider ?? new CounterModeKeyDerivationProvider();
            byte[] signingKey = DeriveSigningKey(inputs, provider);
            byte[] applicationKey = DeriveApplicationKey(inputs, provider);
            byte[] encryptionKey = DeriveEncryptionKey(inputs, provider);
            byte[] decryptionKey = DeriveDecryptionKey(inputs, provider);
            return new SmbSessionKeySet(signingKey, applicationKey, encryptionKey, decryptionKey);
        }

        /// <summary>
        /// Derive the SMB signing key for the supplied session inputs.
        /// </summary>
        /// <param name="inputs">Dialect, cipher, and session-key inputs.</param>
        /// <param name="keyDerivationProvider">Optional key-derivation provider override.</param>
        /// <returns>Derived signing-key bytes.</returns>
        public static byte[] DeriveSigningKey(SmbKeyDerivationInputs inputs, IKeyDerivationProvider? keyDerivationProvider = null)
        {
            if (inputs == null)
            {
                throw new ArgumentNullException(nameof(inputs), "Inputs cannot be null.");
            }

            IKeyDerivationProvider provider = keyDerivationProvider ?? new CounterModeKeyDerivationProvider();
            return provider.DeriveKey(
                inputs.SessionKey,
                GetSigningLabel(inputs.Dialect),
                GetSigningContext(inputs),
                GetOutputLength(inputs));
        }

        /// <summary>
        /// Derive the SMB application key for the supplied session inputs.
        /// </summary>
        /// <param name="inputs">Dialect, cipher, and session-key inputs.</param>
        /// <param name="keyDerivationProvider">Optional key-derivation provider override.</param>
        /// <returns>Derived application-key bytes.</returns>
        public static byte[] DeriveApplicationKey(SmbKeyDerivationInputs inputs, IKeyDerivationProvider? keyDerivationProvider = null)
        {
            if (inputs == null)
            {
                throw new ArgumentNullException(nameof(inputs), "Inputs cannot be null.");
            }

            IKeyDerivationProvider provider = keyDerivationProvider ?? new CounterModeKeyDerivationProvider();
            return provider.DeriveKey(
                inputs.SessionKey,
                GetApplicationLabel(inputs.Dialect),
                GetApplicationContext(inputs),
                GetOutputLength(inputs));
        }

        /// <summary>
        /// Derive the SMB encryption key for the supplied session inputs.
        /// </summary>
        /// <param name="inputs">Dialect, cipher, and session-key inputs.</param>
        /// <param name="keyDerivationProvider">Optional key-derivation provider override.</param>
        /// <returns>Derived encryption-key bytes.</returns>
        public static byte[] DeriveEncryptionKey(SmbKeyDerivationInputs inputs, IKeyDerivationProvider? keyDerivationProvider = null)
        {
            if (inputs == null)
            {
                throw new ArgumentNullException(nameof(inputs), "Inputs cannot be null.");
            }

            IKeyDerivationProvider provider = keyDerivationProvider ?? new CounterModeKeyDerivationProvider();
            ReadOnlySpan<byte> keyDerivationSecret = GetEncryptionDerivationSecret(inputs);
            return provider.DeriveKey(
                keyDerivationSecret,
                GetEncryptionLabel(inputs.Dialect),
                GetEncryptionContext(inputs),
                GetOutputLength(inputs));
        }

        /// <summary>
        /// Derive the SMB decryption key for the supplied session inputs.
        /// </summary>
        /// <param name="inputs">Dialect, cipher, and session-key inputs.</param>
        /// <param name="keyDerivationProvider">Optional key-derivation provider override.</param>
        /// <returns>Derived decryption-key bytes.</returns>
        public static byte[] DeriveDecryptionKey(SmbKeyDerivationInputs inputs, IKeyDerivationProvider? keyDerivationProvider = null)
        {
            if (inputs == null)
            {
                throw new ArgumentNullException(nameof(inputs), "Inputs cannot be null.");
            }

            IKeyDerivationProvider provider = keyDerivationProvider ?? new CounterModeKeyDerivationProvider();
            ReadOnlySpan<byte> keyDerivationSecret = GetEncryptionDerivationSecret(inputs);
            return provider.DeriveKey(
                keyDerivationSecret,
                GetDecryptionLabel(inputs.Dialect),
                GetDecryptionContext(inputs),
                GetOutputLength(inputs));
        }

        private static byte[] GetSigningLabel(SmbDialect dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("SMB2AESCMAC");
                case SmbDialect.Smb311:
                    return Encoding.ASCII.GetBytes("SMBSigningKey");
                default:
                    throw new NotSupportedException("Signing-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetApplicationLabel(SmbDialect dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("SMB2APP");
                case SmbDialect.Smb311:
                    return Encoding.ASCII.GetBytes("SMBAppKey");
                default:
                    throw new NotSupportedException("Application-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetEncryptionLabel(SmbDialect dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("SMB2AESCCM");
                case SmbDialect.Smb311:
                    return Encoding.ASCII.GetBytes("SMBS2CCipherKey");
                default:
                    throw new NotSupportedException("Encryption-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetDecryptionLabel(SmbDialect dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("SMB2AESCCM");
                case SmbDialect.Smb311:
                    return Encoding.ASCII.GetBytes("SMBC2SCipherKey");
                default:
                    throw new NotSupportedException("Decryption-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetSigningContext(SmbKeyDerivationInputs inputs)
        {
            switch (inputs.Dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("SmbSign\0");
                case SmbDialect.Smb311:
                    return RequirePreauthHash(inputs);
                default:
                    throw new NotSupportedException("Signing-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetApplicationContext(SmbKeyDerivationInputs inputs)
        {
            switch (inputs.Dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("SmbRpc\0");
                case SmbDialect.Smb311:
                    return RequirePreauthHash(inputs);
                default:
                    throw new NotSupportedException("Application-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetEncryptionContext(SmbKeyDerivationInputs inputs)
        {
            switch (inputs.Dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("ServerOut\0");
                case SmbDialect.Smb311:
                    return RequirePreauthHash(inputs);
                default:
                    throw new NotSupportedException("Encryption-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] GetDecryptionContext(SmbKeyDerivationInputs inputs)
        {
            switch (inputs.Dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return Encoding.ASCII.GetBytes("ServerIn \0");
                case SmbDialect.Smb311:
                    return RequirePreauthHash(inputs);
                default:
                    throw new NotSupportedException("Decryption-key derivation is defined only for SMB 3.x dialects.");
            }
        }

        private static byte[] RequirePreauthHash(SmbKeyDerivationInputs inputs)
        {
            if (inputs.PreauthIntegrityHash.Length == 0)
            {
                throw new ArgumentException("SMB 3.1.1 key derivation requires a preauthentication transcript hash.", nameof(inputs));
            }

            return inputs.PreauthIntegrityHash;
        }

        private static ReadOnlySpan<byte> GetEncryptionDerivationSecret(SmbKeyDerivationInputs inputs)
        {
            if (inputs.Dialect == SmbDialect.Smb311 &&
                (inputs.CipherAlgorithmId == SmbCipherAlgorithmId.Aes256Ccm || inputs.CipherAlgorithmId == SmbCipherAlgorithmId.Aes256Gcm))
            {
                if (inputs.FullSessionKey.Length == 0)
                {
                    throw new ArgumentException("SMB 3.1.1 AES-256 key derivation requires a full session key.", nameof(inputs));
                }

                return inputs.FullSessionKey;
            }

            return inputs.SessionKey;
        }

        private static int GetOutputLength(SmbKeyDerivationInputs inputs)
        {
            switch (inputs.Dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    if (inputs.CipherAlgorithmId != SmbCipherAlgorithmId.Aes128Ccm)
                    {
                        throw new NotSupportedException("SMB 3.0 and SMB 3.0.2 currently support only AES-128-CCM key lengths.");
                    }

                    return 16;
                case SmbDialect.Smb311:
                    switch (inputs.CipherAlgorithmId)
                    {
                        case SmbCipherAlgorithmId.Aes128Ccm:
                        case SmbCipherAlgorithmId.Aes128Gcm:
                            return 16;
                        case SmbCipherAlgorithmId.Aes256Ccm:
                        case SmbCipherAlgorithmId.Aes256Gcm:
                            return 32;
                        default:
                            throw new NotSupportedException("The negotiated SMB 3.1.1 cipher identifier is not supported.");
                    }
                default:
                    throw new NotSupportedException("SMB subkey derivation is defined only for SMB 3.x dialects.");
            }
        }
    }
}
