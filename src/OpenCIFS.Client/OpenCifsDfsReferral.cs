namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Bounded DFS referral returned by the OpenCIFS client surface.
    /// </summary>
    public sealed class OpenCifsDfsReferral
    {
        /// <summary>
        /// Requested DFS path that produced the referral response.
        /// </summary>
        public string RequestedPath { get; set; } = string.Empty;

        /// <summary>
        /// Referral-path prefix matched by the server.
        /// </summary>
        public string ReferralPath { get; set; } = string.Empty;

        /// <summary>
        /// Returned target network address.
        /// </summary>
        public string NetworkAddress { get; set; } = string.Empty;

        /// <summary>
        /// Parsed target server name.
        /// </summary>
        public string TargetServerName { get; set; } = string.Empty;

        /// <summary>
        /// Parsed target share name.
        /// </summary>
        public string TargetShareName { get; set; } = string.Empty;

        /// <summary>
        /// Parsed relative target path beneath <see cref="TargetShareName" />.
        /// </summary>
        public string TargetPath { get; set; } = string.Empty;

        /// <summary>
        /// Number of request-path bytes consumed by the referral prefix.
        /// </summary>
        public ushort PathConsumed { get; set; }

        /// <summary>
        /// Referral time-to-live, in seconds.
        /// </summary>
        public uint TimeToLiveSeconds { get; set; }

        /// <summary>
        /// Absolute UTC expiration timestamp computed from <see cref="TimeToLiveSeconds" />.
        /// </summary>
        public DateTime ExpiresAtUtc { get; set; }

        /// <summary>
        /// Whether the entry points at another DFS root target instead of a final storage target.
        /// </summary>
        public bool IsRootTarget { get; set; }
    }
}
