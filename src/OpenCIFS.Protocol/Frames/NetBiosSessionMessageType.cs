namespace OpenCIFS.Protocol
{
    /// <summary>
    /// NetBIOS session service message types.
    /// </summary>
    public enum NetBiosSessionMessageType : byte
    {
        /// <summary>
        /// Session message.
        /// </summary>
        SessionMessage = 0x00,

        /// <summary>
        /// Session request.
        /// </summary>
        SessionRequest = 0x81,

        /// <summary>
        /// Positive session response.
        /// </summary>
        PositiveSessionResponse = 0x82,

        /// <summary>
        /// Negative session response.
        /// </summary>
        NegativeSessionResponse = 0x83,

        /// <summary>
        /// Retarget response.
        /// </summary>
        RetargetSessionResponse = 0x84,

        /// <summary>
        /// Session keep-alive.
        /// </summary>
        SessionKeepAlive = 0x85
    }
}

