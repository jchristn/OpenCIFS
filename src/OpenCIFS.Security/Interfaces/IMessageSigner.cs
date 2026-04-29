namespace OpenCIFS.Security
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Signs and verifies SMB messages using a concrete negotiated algorithm.
    /// </summary>
    public interface IMessageSigner
    {
        /// <summary>
        /// Negotiated signing algorithm identifier.
        /// </summary>
        SigningAlgorithmId AlgorithmId { get; }

        /// <summary>
        /// Size of a produced signature in bytes.
        /// </summary>
        int SignatureLength { get; }

        /// <summary>
        /// Indicates whether the signing algorithm requires a caller-supplied nonce.
        /// </summary>
        bool RequiresNonce { get; }

        /// <summary>
        /// Sign a binary message using the supplied signing key and optional nonce.
        /// </summary>
        /// <param name="message">Message bytes.</param>
        /// <param name="signingKey">Signing key bytes.</param>
        /// <param name="nonce">Algorithm-specific nonce bytes. Pass an empty span when the algorithm does not require a nonce.</param>
        /// <returns>Signature bytes.</returns>
        byte[] Sign(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce);

        /// <summary>
        /// Verify a signature for a binary message using the supplied signing key and optional nonce.
        /// </summary>
        /// <param name="message">Message bytes.</param>
        /// <param name="signingKey">Signing key bytes.</param>
        /// <param name="nonce">Algorithm-specific nonce bytes. Pass an empty span when the algorithm does not require a nonce.</param>
        /// <param name="signature">Signature bytes.</param>
        /// <returns><c>true</c> if the signature is valid.</returns>
        bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signingKey, ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> signature);
    }
}
