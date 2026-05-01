namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Pure-function selector that picks the strongest SMB 3.1.1 negotiate-context algorithms
    /// supported by the bounded OpenCIFS managed stack from the client-offered context payloads.
    /// </summary>
    /// <remarks>
    /// This selector encapsulates the algorithm choices that SMB 3.1.1 negotiate-time wiring will
    /// need once dialect advertisement is enabled. The bounded supported set is currently:
    /// preauth integrity SHA-512, signing AES-CMAC and HMAC-SHA256 (AES-GMAC declined until per-message
    /// signing wiring lands), and encryption AES-128-CCM (other ciphers declined until negotiation
    /// wiring lands and the extended-key-derivation paths are exercised).
    /// </remarks>
    public static class Smb311NegotiateContextSelector
    {
        /// <summary>
        /// Select the preauth integrity hash algorithm.
        /// </summary>
        /// <param name="clientCapabilities">Client-offered preauth integrity capabilities.</param>
        /// <returns>Selected preauth hash algorithm identifier.</returns>
        public static HashAlgorithmId SelectPreauthHashAlgorithm(PreauthIntegrityCapabilities clientCapabilities)
        {
            if (clientCapabilities == null)
            {
                throw new ArgumentNullException(nameof(clientCapabilities), "ClientCapabilities cannot be null.");
            }

            for (int index = 0; index < clientCapabilities.HashAlgorithms.Length; index++)
            {
                if (clientCapabilities.HashAlgorithms[index] == HashAlgorithmId.Sha512)
                {
                    return HashAlgorithmId.Sha512;
                }
            }

            throw new ProtocolEncodingException("The client did not offer a supported SMB 3.1.1 preauth integrity hash algorithm.");
        }

        /// <summary>
        /// Select the signing algorithm. Returns <see cref="SigningAlgorithmId.HmacSha256" /> when no signing context is present.
        /// Prefers AES-GMAC when offered, then AES-CMAC, then HMAC-SHA256.
        /// </summary>
        /// <param name="clientCapabilities">Client-offered signing capabilities, or <c>null</c> when no context was sent.</param>
        /// <returns>Selected signing algorithm identifier.</returns>
        public static SigningAlgorithmId SelectSigningAlgorithm(SigningCapabilities? clientCapabilities)
        {
            if (clientCapabilities == null)
            {
                return SigningAlgorithmId.HmacSha256;
            }

            for (int index = 0; index < clientCapabilities.SigningAlgorithms.Length; index++)
            {
                if (clientCapabilities.SigningAlgorithms[index] == SigningAlgorithmId.AesGmac)
                {
                    return SigningAlgorithmId.AesGmac;
                }
            }

            for (int index = 0; index < clientCapabilities.SigningAlgorithms.Length; index++)
            {
                if (clientCapabilities.SigningAlgorithms[index] == SigningAlgorithmId.AesCmac)
                {
                    return SigningAlgorithmId.AesCmac;
                }
            }

            for (int index = 0; index < clientCapabilities.SigningAlgorithms.Length; index++)
            {
                if (clientCapabilities.SigningAlgorithms[index] == SigningAlgorithmId.HmacSha256)
                {
                    return SigningAlgorithmId.HmacSha256;
                }
            }

            throw new ProtocolEncodingException("The client did not offer a supported SMB 3.1.1 signing algorithm.");
        }

        /// <summary>
        /// Select the encryption cipher, or <c>null</c> when no encryption context is present.
        /// Prefers AES-128-GCM when offered, otherwise falls back to AES-128-CCM.
        /// </summary>
        /// <param name="clientCapabilities">Client-offered encryption capabilities, or <c>null</c> when no context was sent.</param>
        /// <returns>Selected cipher identifier, or <c>null</c> when encryption is not negotiated.</returns>
        public static SmbCipherAlgorithmId? SelectCipher(EncryptionCapabilities? clientCapabilities)
        {
            if (clientCapabilities == null)
            {
                return null;
            }

            for (int index = 0; index < clientCapabilities.Ciphers.Length; index++)
            {
                if (clientCapabilities.Ciphers[index] == SmbCipherAlgorithmId.Aes128Gcm)
                {
                    return SmbCipherAlgorithmId.Aes128Gcm;
                }
            }

            for (int index = 0; index < clientCapabilities.Ciphers.Length; index++)
            {
                if (clientCapabilities.Ciphers[index] == SmbCipherAlgorithmId.Aes128Ccm)
                {
                    return SmbCipherAlgorithmId.Aes128Ccm;
                }
            }

            throw new ProtocolEncodingException("The client did not offer a supported SMB 3.1.1 encryption cipher.");
        }
    }
}
