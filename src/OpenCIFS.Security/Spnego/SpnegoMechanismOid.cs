namespace OpenCIFS.Security
{
    /// <summary>
    /// Common SPNEGO and GSS mechanism object identifiers.
    /// </summary>
    public static class SpnegoMechanismOid
    {
        /// <summary>
        /// SPNEGO pseudo-mechanism OID.
        /// </summary>
        public const string Spnego = "1.3.6.1.5.5.2";

        /// <summary>
        /// Kerberos V5 mechanism OID.
        /// </summary>
        public const string Kerberos = "1.2.840.113554.1.2.2";

        /// <summary>
        /// Microsoft Kerberos U2U mechanism OID.
        /// </summary>
        public const string MicrosoftKerberos = "1.2.840.48018.1.2.2";

        /// <summary>
        /// NTLMSSP mechanism OID.
        /// </summary>
        public const string Ntlm = "1.3.6.1.4.1.311.2.2.10";
    }
}
