namespace OpenCIFS.Security
{
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Signs SMB 3.1.1 messages with AES-GMAC.
    /// </summary>
    public sealed class AesGmacMessageSigner : IMessageSigner
    {
        /// <inheritdoc />
        public SigningAlgorithmId AlgorithmId => SigningAlgorithmId.AesGmac;

        /// <inheritdoc />
        public int SignatureLength => 16;

        /// <inheritdoc />
        public bool RequiresNonce => true;

        /// <inheritdoc />
        public byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce)
        {
            return AesGmac.ComputeMac(signingKey, nonce, message);
        }

        /// <inheritdoc />
        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature)
        {
            return AesGmac.Verify(signingKey, nonce, message, signature);
        }
    }
}
