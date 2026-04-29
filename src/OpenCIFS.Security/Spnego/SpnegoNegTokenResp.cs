namespace OpenCIFS.Security
{
    /// <summary>
    /// Represents a SPNEGO <c>NegTokenResp</c> message.
    /// </summary>
    public sealed class SpnegoNegTokenResp
    {
        /// <summary>
        /// Optional negotiation-state value.
        /// </summary>
        public SpnegoNegState? NegotiationState { get; set; }

        /// <summary>
        /// Optional selected mechanism OID.
        /// </summary>
        public string? SupportedMechanism { get; set; }

        /// <summary>
        /// Optional mechanism response token.
        /// </summary>
        public byte[]? ResponseToken { get; set; }

        /// <summary>
        /// Optional mechanism-list MIC bytes.
        /// </summary>
        public byte[]? MechanismListMic { get; set; }
    }
}
