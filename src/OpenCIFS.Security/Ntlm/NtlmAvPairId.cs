namespace OpenCIFS.Security
{
    /// <summary>
    /// NTLM AV pair identifiers used in target-info and client-challenge structures.
    /// </summary>
    public enum NtlmAvPairId : ushort
    {
        /// <summary>
        /// Terminates the AV pair list.
        /// </summary>
        EndOfList = 0x0000,

        /// <summary>
        /// NetBIOS computer name.
        /// </summary>
        NetBiosComputerName = 0x0001,

        /// <summary>
        /// NetBIOS domain name.
        /// </summary>
        NetBiosDomainName = 0x0002,

        /// <summary>
        /// DNS computer name.
        /// </summary>
        DnsComputerName = 0x0003,

        /// <summary>
        /// DNS domain name.
        /// </summary>
        DnsDomainName = 0x0004,

        /// <summary>
        /// DNS tree name.
        /// </summary>
        DnsTreeName = 0x0005,

        /// <summary>
        /// AV flags value.
        /// </summary>
        Flags = 0x0006,

        /// <summary>
        /// Server timestamp.
        /// </summary>
        Timestamp = 0x0007,

        /// <summary>
        /// Single-host data.
        /// </summary>
        SingleHost = 0x0008,

        /// <summary>
        /// Service principal target name.
        /// </summary>
        TargetName = 0x0009,

        /// <summary>
        /// Channel-binding hash.
        /// </summary>
        ChannelBindings = 0x000A
    }
}
