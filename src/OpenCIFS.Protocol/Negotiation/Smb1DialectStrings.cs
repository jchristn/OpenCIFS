namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Well-known SMB1/CIFS dialect strings used during multi-protocol negotiate.
    /// </summary>
    public static class Smb1DialectStrings
    {
        /// <summary>
        /// MS-SMB / MS-CIFS LANMAN1.0 dialect string.
        /// </summary>
        public const string LanMan10 = "LANMAN1.0";

        /// <summary>
        /// MS-SMB / MS-CIFS LM1.2X002 dialect string.
        /// </summary>
        public const string LanMan12 = "LM1.2X002";

        /// <summary>
        /// MS-SMB / MS-CIFS LANMAN2.1 dialect string.
        /// </summary>
        public const string LanMan21 = "LANMAN2.1";

        /// <summary>
        /// MS-SMB / MS-CIFS NT LM 0.12 dialect string. Required for SMB1 extended-security negotiate.
        /// </summary>
        public const string NtLm012 = "NT LM 0.12";

        /// <summary>
        /// MS-SMB2 SMB 2.002 multi-protocol bridge dialect string sent as an SMB1 negotiate entry.
        /// </summary>
        public const string Smb2002 = "SMB 2.002";

        /// <summary>
        /// MS-SMB2 SMB 2.??? multi-protocol bridge dialect string sent as an SMB1 negotiate entry.
        /// </summary>
        public const string Smb2Wildcard = "SMB 2.???";
    }
}
