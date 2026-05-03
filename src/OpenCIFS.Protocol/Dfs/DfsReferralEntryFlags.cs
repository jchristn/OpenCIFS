namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Per-entry referral flags carried in the V3/V4 DFS referral entry shape per
    /// MS-DFSC section 2.2.5.4.
    /// </summary>
    [Flags]
    public enum DfsReferralEntryFlags : ushort
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// The entry uses the NameList referral layout (special name + expanded names) instead
        /// of the path-consumer DFS path / alternate-path / network-address layout. Used for DC
        /// referrals and domain referrals.
        /// </summary>
        NameListReferral = 0x0002,

        /// <summary>
        /// Target set boundary (DFS V4 only): the entry marks the start of a target set used by
        /// DFS target failback grouping.
        /// </summary>
        TargetSetBoundary = 0x0004
    }
}
