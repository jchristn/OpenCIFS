namespace OpenCIFS.Security
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Creates concrete SMB message signers for negotiated algorithms.
    /// </summary>
    public static class MessageSignerFactory
    {
        /// <summary>
        /// Create a signer for the supplied SMB signing algorithm.
        /// </summary>
        /// <param name="algorithmId">Negotiated signing algorithm identifier.</param>
        /// <returns>Concrete signer instance.</returns>
        public static IMessageSigner Create(SigningAlgorithmId algorithmId)
        {
            switch (algorithmId)
            {
                case SigningAlgorithmId.HmacSha256:
                    return new HmacSha256MessageSigner();
                case SigningAlgorithmId.AesCmac:
                    return new AesCmacMessageSigner();
                case SigningAlgorithmId.AesGmac:
                    return new AesGmacMessageSigner();
                default:
                    throw new NotSupportedException("The negotiated SMB signing algorithm is not supported.");
            }
        }
    }
}
