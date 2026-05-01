namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// DFS referral-header flags.
    /// </summary>
    [Flags]
    public enum DfsReferralHeaderFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// All returned targets can service further DFS referral requests.
        /// </summary>
        ReferralServers = 0x00000001,

        /// <summary>
        /// All returned targets are final storage targets.
        /// </summary>
        StorageServers = 0x00000002,

        /// <summary>
        /// Target failback is enabled.
        /// </summary>
        TargetFailback = 0x00000004
    }
}
