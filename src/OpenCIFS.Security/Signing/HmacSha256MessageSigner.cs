namespace OpenCIFS.Security
{
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Signs SMB 2.x messages with truncated HMAC-SHA256.
    /// </summary>
    public sealed class HmacSha256MessageSigner : IMessageSigner
    {
        private const int SmbSignatureLength = 16;

        /// <inheritdoc />
        public SigningAlgorithmId AlgorithmId => SigningAlgorithmId.HmacSha256;

        /// <inheritdoc />
        public int SignatureLength => SmbSignatureLength;

        /// <inheritdoc />
        public bool RequiresNonce => false;

        /// <inheritdoc />
        public byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce)
        {
            ValidateNonce(nonce);
            using HMACSHA256 algorithm = new HMACSHA256(signingKey.ToArray());
            byte[] hash = algorithm.ComputeHash(message.ToArray());
            byte[] signature = new byte[SmbSignatureLength];
            Buffer.BlockCopy(hash, 0, signature, 0, signature.Length);
            return signature;
        }

        /// <inheritdoc />
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature)
        {
            if (signature.Length != SmbSignatureLength)
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
                throw new ArgumentException("HMAC-SHA256 SMB signing does not accept a nonce.", nameof(nonce));
            }
        }
    }
}
