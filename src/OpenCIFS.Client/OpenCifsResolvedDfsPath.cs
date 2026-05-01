namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Bounded resolved DFS target path.
    /// </summary>
    public sealed class OpenCifsResolvedDfsPath
    {
        /// <summary>
        /// Original DFS path that was resolved.
        /// </summary>
        public string OriginalPath { get; set; } = string.Empty;

        /// <summary>
        /// Matched DFS namespace prefix.
        /// </summary>
        public string ReferralPath { get; set; } = string.Empty;

        /// <summary>
        /// Target server name.
        /// </summary>
        public string TargetServerName { get; set; } = string.Empty;

        /// <summary>
        /// Target share name.
        /// </summary>
        public string TargetShareName { get; set; } = string.Empty;

        /// <summary>
        /// Relative target path beneath <see cref="TargetShareName" /> after combining the referral target with the unresolved suffix.
        /// </summary>
        public string TargetRelativePath { get; set; } = string.Empty;

        /// <summary>
        /// Combined target UNC path.
        /// </summary>
        public string TargetUncPath { get; set; } = string.Empty;

        /// <summary>
        /// Absolute UTC expiration timestamp for the cached referral used to resolve the path.
        /// </summary>
        public DateTime ExpiresAtUtc { get; set; }

        /// <summary>
        /// Whether the resolved path came from the client referral cache instead of a fresh remote query.
        /// </summary>
        public bool WasResolvedFromCache { get; set; }

        /// <summary>
        /// Whether the resolved target stays on the same SMB server name as the current OpenCIFS client connection.
        /// </summary>
        public bool IsSameServer { get; set; }
    }
}
