namespace OpenCIFS.Security
{
    using System;

    /// <summary>
    /// Maps OpenCIFS authentication mechanisms to the SPNEGO mechanism OIDs used on the wire.
    /// </summary>
    public static class OpenCifsAuthenticationMechanismCatalog
    {
        /// <summary>
        /// Get the SPNEGO mechanism OIDs associated with the supplied authentication mechanism.
        /// </summary>
        /// <param name="mechanism">Authentication mechanism.</param>
        /// <returns>Advertised SPNEGO mechanism OIDs in preference order.</returns>
        public static string[] GetSpnegoMechanismOids(OpenCifsAuthenticationMechanism mechanism)
        {
            switch (mechanism)
            {
                case OpenCifsAuthenticationMechanism.Ntlm:
                    return new string[] { SpnegoMechanismOid.Ntlm };
                case OpenCifsAuthenticationMechanism.Kerberos:
                    return new string[] { SpnegoMechanismOid.Kerberos, SpnegoMechanismOid.MicrosoftKerberos };
                default:
                    throw new ArgumentOutOfRangeException(nameof(mechanism), "The authentication mechanism is not recognized.");
            }
        }

        /// <summary>
        /// Try to map a SPNEGO mechanism OID to an OpenCIFS authentication mechanism.
        /// </summary>
        /// <param name="mechanismOid">SPNEGO mechanism OID.</param>
        /// <param name="mechanism">Mapped OpenCIFS mechanism when recognized.</param>
        /// <returns><c>true</c> when the OID is recognized; otherwise <c>false</c>.</returns>
        public static bool TryGetAuthenticationMechanism(string? mechanismOid, out OpenCifsAuthenticationMechanism mechanism)
        {
            if (string.Equals(mechanismOid, SpnegoMechanismOid.Ntlm, StringComparison.Ordinal))
            {
                mechanism = OpenCifsAuthenticationMechanism.Ntlm;
                return true;
            }

            if (string.Equals(mechanismOid, SpnegoMechanismOid.Kerberos, StringComparison.Ordinal) ||
                string.Equals(mechanismOid, SpnegoMechanismOid.MicrosoftKerberos, StringComparison.Ordinal))
            {
                mechanism = OpenCifsAuthenticationMechanism.Kerberos;
                return true;
            }

            mechanism = default;
            return false;
        }

        /// <summary>
        /// Determine whether the supplied SPNEGO mechanism OID identifies Kerberos.
        /// </summary>
        /// <param name="mechanismOid">SPNEGO mechanism OID.</param>
        /// <returns><c>true</c> when the OID identifies Kerberos; otherwise <c>false</c>.</returns>
        public static bool IsKerberosMechanismOid(string? mechanismOid)
        {
            return string.Equals(mechanismOid, SpnegoMechanismOid.Kerberos, StringComparison.Ordinal) ||
                string.Equals(mechanismOid, SpnegoMechanismOid.MicrosoftKerberos, StringComparison.Ordinal);
        }
    }
}
