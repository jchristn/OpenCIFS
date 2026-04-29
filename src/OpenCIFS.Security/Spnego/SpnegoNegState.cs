namespace OpenCIFS.Security
{
    /// <summary>
    /// SPNEGO negotiation-state values.
    /// </summary>
    public enum SpnegoNegState
    {
        /// <summary>
        /// Mechanism negotiation completed successfully.
        /// </summary>
        AcceptCompleted = 0,

        /// <summary>
        /// Mechanism negotiation succeeded but requires additional tokens.
        /// </summary>
        AcceptIncomplete = 1,

        /// <summary>
        /// Mechanism negotiation failed.
        /// </summary>
        Reject = 2,

        /// <summary>
        /// The initiator must supply a mechanism-list MIC.
        /// </summary>
        RequestMic = 3
    }
}
