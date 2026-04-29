namespace OpenCIFS.Security
{
    /// <summary>
    /// NTLMSSP message types.
    /// </summary>
    public enum NtlmMessageType : uint
    {
        /// <summary>
        /// NTLMSSP negotiate message.
        /// </summary>
        Negotiate = 0x00000001U,

        /// <summary>
        /// NTLMSSP challenge message.
        /// </summary>
        Challenge = 0x00000002U,

        /// <summary>
        /// NTLMSSP authenticate message.
        /// </summary>
        Authenticate = 0x00000003U
    }
}
