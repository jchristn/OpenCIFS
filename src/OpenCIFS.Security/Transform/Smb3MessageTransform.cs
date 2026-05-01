namespace OpenCIFS.Security
{
    using System;
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Encrypts and decrypts bounded SMB 3.0 / 3.0.2 transform packets.
    /// </summary>
    public static class Smb3MessageTransform
    {
        private const int AesCcmNonceLength = 11;
        private const int AesGcmNonceLength = 12;
        private const int TransformHeaderLength = 52;

        /// <summary>
        /// Encrypt an SMB2 packet with the SMB3 transform header using the negotiated cipher.
        /// </summary>
        /// <param name="plaintextPacket">Unencrypted SMB2 packet bytes.</param>
        /// <param name="sessionId">Owning authenticated session identifier.</param>
        /// <param name="encryptionKey">Outbound SMB3 encryption key.</param>
        /// <param name="cipher">Negotiated cipher algorithm. Defaults to AES-128-CCM.</param>
        /// <returns>Serialized SMB3 transform packet.</returns>
        public static byte[] EncryptPacket(
            ReadOnlySpan<byte> plaintextPacket,
            ulong sessionId,
            ReadOnlySpan<byte> encryptionKey,
            SmbCipherAlgorithmId cipher = SmbCipherAlgorithmId.Aes128Ccm)
        {
            if (plaintextPacket.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(plaintextPacket), "The SMB3 transform packet plaintext must not be empty.");
            }

            if (sessionId == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sessionId), "The SMB3 transform packet requires a non-zero session identifier.");
            }

            if (encryptionKey.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(encryptionKey), "The SMB3 transform packet encryption key must not be empty.");
            }

            int nonceLength = GetNonceLength(cipher);
            byte[] fullNonce = new byte[16];
            RandomNumberGenerator.Fill(fullNonce.AsSpan(0, nonceLength));

            Smb2TransformHeader header = new Smb2TransformHeader
            {
                Signature = new byte[16],
                Nonce = fullNonce,
                OriginalMessageSize = checked((uint)plaintextPacket.Length),
                SessionId = sessionId
            };

            AeadCipherResult cipherResult = cipher switch
            {
                SmbCipherAlgorithmId.Aes128Ccm => AesCcmCipher.Encrypt(
                    encryptionKey,
                    fullNonce.AsSpan(0, nonceLength),
                    plaintextPacket,
                    header.GetAuthenticatedData()),
                SmbCipherAlgorithmId.Aes128Gcm => AesGcmCipher.Encrypt(
                    encryptionKey,
                    fullNonce.AsSpan(0, nonceLength),
                    plaintextPacket,
                    header.GetAuthenticatedData()),
                _ => throw new NotSupportedException("The SMB3 transform layer currently supports only AES-128-CCM and AES-128-GCM ciphers.")
            };

            header.Signature = cipherResult.AuthenticationTag;

            byte[] headerBytes = header.ToByteArray();
            byte[] transformedPacket = new byte[headerBytes.Length + cipherResult.Ciphertext.Length];
            Buffer.BlockCopy(headerBytes, 0, transformedPacket, 0, headerBytes.Length);
            Buffer.BlockCopy(cipherResult.Ciphertext, 0, transformedPacket, headerBytes.Length, cipherResult.Ciphertext.Length);
            return transformedPacket;
        }

        /// <summary>
        /// Decrypt an SMB3 transform packet to the original SMB2 message bytes using the negotiated cipher.
        /// </summary>
        /// <param name="transformPacket">Serialized SMB3 transform packet.</param>
        /// <param name="decryptionKey">Inbound SMB3 decryption key.</param>
        /// <param name="expectedSessionId">Optional expected session identifier.</param>
        /// <param name="cipher">Negotiated cipher algorithm. Defaults to AES-128-CCM.</param>
        /// <returns>Decrypted SMB2 packet bytes.</returns>
        public static byte[] DecryptPacket(
            ReadOnlyMemory<byte> transformPacket,
            ReadOnlySpan<byte> decryptionKey,
            ulong? expectedSessionId = null,
            SmbCipherAlgorithmId cipher = SmbCipherAlgorithmId.Aes128Ccm)
        {
            if (decryptionKey.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(decryptionKey), "The SMB3 transform packet decryption key must not be empty.");
            }

            Smb2TransformHeader header = Smb2TransformHeader.ReadFrom(transformPacket);

            if (expectedSessionId.HasValue && header.SessionId != expectedSessionId.Value)
            {
                throw new ProtocolValidationException("The SMB3 transform packet session identifier does not match the expected authenticated session.", nameof(transformPacket));
            }

            int encryptedPayloadLength = transformPacket.Length - TransformHeaderLength;

            if (encryptedPayloadLength <= 0)
            {
                throw new ProtocolEncodingException("The SMB3 transform packet does not contain an encrypted SMB2 payload.");
            }

            if (header.OriginalMessageSize == 0 || encryptedPayloadLength != checked((int)header.OriginalMessageSize))
            {
                throw new ProtocolEncodingException("The SMB3 transform packet payload length does not match the declared original message size.");
            }

            int nonceLength = GetNonceLength(cipher);
            ReadOnlySpan<byte> ciphertext = transformPacket.Span.Slice(TransformHeaderLength);

            try
            {
                return cipher switch
                {
                    SmbCipherAlgorithmId.Aes128Ccm => AesCcmCipher.Decrypt(
                        decryptionKey,
                        header.Nonce.AsSpan(0, nonceLength),
                        ciphertext,
                        header.Signature,
                        header.GetAuthenticatedData()),
                    SmbCipherAlgorithmId.Aes128Gcm => AesGcmCipher.Decrypt(
                        decryptionKey,
                        header.Nonce.AsSpan(0, nonceLength),
                        ciphertext,
                        header.Signature,
                        header.GetAuthenticatedData()),
                    _ => throw new NotSupportedException("The SMB3 transform layer currently supports only AES-128-CCM and AES-128-GCM ciphers.")
                };
            }
            catch (CryptographicException exception)
            {
                _ = exception;
                throw new ProtocolValidationException("The SMB3 transform packet authentication tag did not verify.", nameof(transformPacket));
            }
        }

        private static int GetNonceLength(SmbCipherAlgorithmId cipher)
        {
            return cipher switch
            {
                SmbCipherAlgorithmId.Aes128Ccm => AesCcmNonceLength,
                SmbCipherAlgorithmId.Aes128Gcm => AesGcmNonceLength,
                _ => throw new NotSupportedException("The SMB3 transform layer currently supports only AES-128-CCM and AES-128-GCM ciphers.")
            };
        }
    }
}
