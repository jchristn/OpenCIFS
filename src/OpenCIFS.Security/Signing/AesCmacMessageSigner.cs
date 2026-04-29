namespace OpenCIFS.Security
{
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Signs SMB 3.0 and SMB 3.0.2 messages with AES-CMAC.
    /// </summary>
    public sealed class AesCmacMessageSigner : IMessageSigner
    {
        /// <inheritdoc />
        public SigningAlgorithmId AlgorithmId => SigningAlgorithmId.AesCmac;

        /// <inheritdoc />
        public int SignatureLength => 16;

        /// <inheritdoc />
        public bool RequiresNonce => false;

        /// <inheritdoc />
        public byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce)
        {
            ValidateNonce(nonce);
            return AesCmac.ComputeMac(signingKey, message);
        }

        /// <inheritdoc />
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != SignatureLength)
            {
                return false;
            }

            byte[] expected = Sign(message, signingKey, nonce);
            return CryptographicOperations.FixedTimeEquals(expected, signature);
        }

        private static void ValidateNonce(ReadOnlySpan<byte> nonce)
        {
            if (!nonce.IsEmpty)
            {
                throw new ArgumentException("AES-CMAC SMB signing does not accept a nonce.", nameof(nonce));
            }
        }
    }
}
