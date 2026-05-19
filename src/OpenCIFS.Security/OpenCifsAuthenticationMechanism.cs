namespace OpenCIFS.Security
{
    /// <summary>
    /// Authentication mechanisms recognized by the bounded OpenCIFS session-setup surface.
    /// </summary>
    public enum OpenCifsAuthenticationMechanism
    {
        /// <summary>
        /// NTLM session setup.
        /// </summary>
        Ntlm = 0,

        /// <summary>
        /// Kerberos session setup.
        /// </summary>
        Kerberos = 1
    }
}
