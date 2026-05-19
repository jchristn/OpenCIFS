namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Immutable validated client settings for the primary OpenCIFS happy-path surface.
    /// </summary>
    public sealed class OpenCifsClientSettings
    {
        /// <summary>
        /// Initialize immutable client settings.
        /// </summary>
        /// <param name="serverName">Remote host name or address.</param>
        /// <param name="serverPort">Remote direct-TCP port.</param>
        /// <param name="minimumDialect">Minimum negotiated dialect.</param>
        /// <param name="maximumDialect">Maximum negotiated dialect.</param>
        /// <param name="requireSigning">Whether signing is required.</param>
        /// <param name="preferEncryption">Whether encryption should be preferred when supported.</param>
        /// <param name="connectTimeoutMs">Connection timeout in milliseconds.</param>
        /// <param name="dfsSiteName">Optional DFS site name for bounded DFS referral requests.</param>
        /// <param name="dfsReferralCacheCapacity">Maximum DFS referral entries retained in the bounded cache.</param>
        /// <param name="enableSmb311Preview">Whether the bounded SMB 3.1.1 preview slice is enabled.</param>
        public OpenCifsClientSettings(
            string serverName,
            int serverPort = 445,
            SmbDialect minimumDialect = SmbDialect.Smb2002,
            SmbDialect maximumDialect = SmbDialect.Smb311,
            bool requireSigning = true,
            bool preferEncryption = true,
            int connectTimeoutMs = 30000,
            string? dfsSiteName = null,
            int dfsReferralCacheCapacity = 128,
            bool enableSmb311Preview = false)
        {
            if (string.IsNullOrWhiteSpace(serverName))
            {
                throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null or whitespace.");
            }

            if (maximumDialect < minimumDialect)
            {
                throw new ArgumentException("MaximumDialect must be greater than or equal to MinimumDialect.", nameof(maximumDialect));
            }

            ServerName = serverName;
            ServerPort = Math.Clamp(serverPort, 1, 65535);
            MinimumDialect = minimumDialect;
            MaximumDialect = maximumDialect;
            RequireSigning = requireSigning;
            PreferEncryption = preferEncryption;
            ConnectTimeoutMs = Math.Clamp(connectTimeoutMs, 1000, 300000);
            DfsSiteName = dfsSiteName ?? string.Empty;
            DfsReferralCacheCapacity = Math.Clamp(dfsReferralCacheCapacity, 1, 65535);
            EnableSmb311Preview = enableSmb311Preview;
        }

        /// <summary>
        /// Remote host name or address.
        /// </summary>
        public string ServerName { get; }

        /// <summary>
        /// Remote direct-TCP port.
        /// </summary>
        public int ServerPort { get; }

        /// <summary>
        /// Minimum negotiated dialect.
        /// </summary>
        public SmbDialect MinimumDialect { get; }

        /// <summary>
        /// Maximum negotiated dialect.
        /// </summary>
        public SmbDialect MaximumDialect { get; }

        /// <summary>
        /// Whether signing is required.
        /// </summary>
        public bool RequireSigning { get; }

        /// <summary>
        /// Whether encryption should be preferred when the negotiated dialect supports it.
        /// </summary>
        public bool PreferEncryption { get; }

        /// <summary>
        /// Connection timeout in milliseconds.
        /// </summary>
        public int ConnectTimeoutMs { get; }

        /// <summary>
        /// Optional DFS site name for bounded DFS referral requests.
        /// </summary>
        public string DfsSiteName { get; }

        /// <summary>
        /// Maximum DFS referral entries retained in the bounded cache.
        /// </summary>
        public int DfsReferralCacheCapacity { get; }

        /// <summary>
        /// Whether the bounded SMB 3.1.1 preview slice is enabled.
        /// </summary>
        public bool EnableSmb311Preview { get; }

        internal OpenCifsClientOptions ToOptions()
        {
            return new OpenCifsClientOptions
            {
                ServerName = ServerName,
                ServerPort = ServerPort,
                MinimumDialect = MinimumDialect,
                MaximumDialect = MaximumDialect,
                RequireSigning = RequireSigning,
                PreferEncryption = PreferEncryption,
                ConnectTimeoutMs = ConnectTimeoutMs,
                DfsSiteName = DfsSiteName,
                DfsReferralCacheCapacity = DfsReferralCacheCapacity,
                EnableSmb311Preview = EnableSmb311Preview
            };
        }
    }
}
