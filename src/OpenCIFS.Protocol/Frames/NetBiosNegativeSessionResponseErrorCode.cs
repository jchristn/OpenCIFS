namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Well-known error codes carried by a NetBIOS NEGATIVE_SESSION_RESPONSE PDU per RFC 1002
    /// section 4.3.4.
    /// </summary>
    public enum NetBiosNegativeSessionResponseErrorCode : byte
    {
        /// <summary>
        /// Not listening on called name.
        /// </summary>
        NotListeningOnCalledName = 0x80,

        /// <summary>
        /// Not listening for calling name.
        /// </summary>
        NotListeningForCallingName = 0x81,

        /// <summary>
        /// Called name not present.
        /// </summary>
        CalledNameNotPresent = 0x82,

        /// <summary>
        /// Called name present but insufficient resources to accept the session.
        /// </summary>
        InsufficientResources = 0x83,

        /// <summary>
        /// Unspecified error.
        /// </summary>
        UnspecifiedError = 0x8F
    }
}
