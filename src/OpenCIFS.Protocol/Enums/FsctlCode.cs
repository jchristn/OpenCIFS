namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Well-known FSCTL codes referenced by the current SMB2 pass-through surface.
    /// </summary>
    public enum FsctlCode : uint
    {
        /// <summary>
        /// DFS referral lookup.
        /// </summary>
        DfsGetReferrals = 0x00060194,

        /// <summary>
        /// Extended DFS referral lookup.
        /// </summary>
        DfsGetReferralsEx = 0x000601B0,

        /// <summary>
        /// Named-pipe transceive operation.
        /// </summary>
        PipeTransceive = 0x0011C017,

        /// <summary>
        /// Named-pipe wait operation.
        /// </summary>
        PipeWait = 0x00110018,

        /// <summary>
        /// Server snapshot enumeration.
        /// </summary>
        SrvEnumerateSnapshots = 0x00144064,

        /// <summary>
        /// Server network-interface query.
        /// </summary>
        QueryNetworkInterfaceInfo = 0x001401FC,

        /// <summary>
        /// Secure negotiate validation.
        /// </summary>
        ValidateNegotiateInfo = 0x00140204
    }
}
