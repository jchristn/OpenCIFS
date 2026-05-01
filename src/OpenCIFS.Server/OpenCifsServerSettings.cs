namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Immutable validated server settings for the primary OpenCIFS server happy-path surface.
    /// </summary>
    public sealed class OpenCifsServerSettings
    {
        /// <summary>
        /// Initialize immutable server settings.
        /// </summary>
        /// <param name="serverName">Server display name.</param>
        /// <param name="bindAddress">Local bind address.</param>
        /// <param name="bindPort">Local bind port.</param>
        /// <param name="shareName">Legacy fallback share name.</param>
        /// <param name="sharePath">Legacy fallback share path.</param>
        /// <param name="minimumDialect">Minimum negotiated dialect.</param>
        /// <param name="maximumDialect">Maximum negotiated dialect.</param>
        /// <param name="requireSigning">Whether signing is required.</param>
        /// <param name="requireNtlmV2">Whether NTLMv2 is required.</param>
        /// <param name="allowAnonymous">Whether anonymous access is allowed.</param>
        /// <param name="enableSmb1">Whether SMB1 is enabled.</param>
        /// <param name="requireEncryptionForSmb3">Whether SMB 3.x sessions require encryption.</param>
        /// <param name="maximumCredits">Maximum SMB2 credits granted to a client.</param>
        /// <param name="enableSmb311Preview">Whether the bounded SMB 3.1.1 preview slice is enabled.</param>
        public OpenCifsServerSettings(
            string serverName,
            string bindAddress,
            int bindPort = 4450,
            string shareName = "share",
            string sharePath = "SampleShare",
            SmbDialect minimumDialect = SmbDialect.Smb2002,
            SmbDialect maximumDialect = SmbDialect.Smb311,
            bool requireSigning = true,
            bool requireNtlmV2 = true,
            bool allowAnonymous = false,
            bool enableSmb1 = false,
            bool requireEncryptionForSmb3 = true,
            int maximumCredits = 64,
            bool enableSmb311Preview = false)
        {
            if (string.IsNullOrWhiteSpace(serverName))
            {
                throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(bindAddress))
            {
                throw new ArgumentNullException(nameof(bindAddress), "BindAddress cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(sharePath))
            {
                throw new ArgumentNullException(nameof(sharePath), "SharePath cannot be null or whitespace.");
            }

            if (maximumDialect < minimumDialect)
            {
                throw new ArgumentException("MaximumDialect must be greater than or equal to MinimumDialect.", nameof(maximumDialect));
            }

            if (!enableSmb1 && minimumDialect == SmbDialect.Cifs10)
            {
                throw new ArgumentException("MinimumDialect cannot be SMB1/CIFS when EnableSmb1 is false.", nameof(minimumDialect));
            }

            ServerName = serverName;
            BindAddress = bindAddress;
            BindPort = Math.Clamp(bindPort, 1, 65535);
            ShareName = shareName;
            SharePath = sharePath;
            MinimumDialect = minimumDialect;
            MaximumDialect = maximumDialect;
            RequireSigning = requireSigning;
            RequireNtlmV2 = requireNtlmV2;
            AllowAnonymous = allowAnonymous;
            EnableSmb1 = enableSmb1;
            RequireEncryptionForSmb3 = requireEncryptionForSmb3;
            MaximumCredits = Math.Clamp(maximumCredits, 1, UInt16.MaxValue);
            EnableSmb311Preview = enableSmb311Preview;
        }

        /// <summary>
        /// Server display name.
        /// </summary>
        public string ServerName { get; }

        /// <summary>
        /// Local bind address.
        /// </summary>
        public string BindAddress { get; }

        /// <summary>
        /// Local bind port.
        /// </summary>
        public int BindPort { get; }

        /// <summary>
        /// Legacy fallback share name exposed when no explicit share registrations are provided.
        /// </summary>
        public string ShareName { get; }

        /// <summary>
        /// Legacy fallback filesystem path used when no explicit share registrations are provided.
        /// </summary>
        public string SharePath { get; }

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
        /// Whether NTLMv2 is required.
        /// </summary>
        public bool RequireNtlmV2 { get; }

        /// <summary>
        /// Whether anonymous access is allowed.
        /// </summary>
        public bool AllowAnonymous { get; }

        /// <summary>
        /// Whether SMB1 is enabled.
        /// </summary>
        public bool EnableSmb1 { get; }

        /// <summary>
        /// Whether SMB 3.x sessions should require encryption.
        /// </summary>
        public bool RequireEncryptionForSmb3 { get; }

        /// <summary>
        /// Maximum SMB2 credits that may be granted to a client on a single connection.
        /// </summary>
        public int MaximumCredits { get; }

        /// <summary>
        /// Whether the bounded SMB 3.1.1 preview slice is enabled.
        /// </summary>
        public bool EnableSmb311Preview { get; }

        internal OpenCifsServerOptions ToOptions()
        {
            return new OpenCifsServerOptions
            {
                ServerName = ServerName,
                BindAddress = BindAddress,
                BindPort = BindPort,
                ShareName = ShareName,
                SharePath = SharePath,
                MinimumDialect = MinimumDialect,
                MaximumDialect = MaximumDialect,
                RequireSigning = RequireSigning,
                RequireNtlmV2 = RequireNtlmV2,
                AllowAnonymous = AllowAnonymous,
                EnableSmb1 = EnableSmb1,
                RequireEncryptionForSmb3 = RequireEncryptionForSmb3,
                MaximumCredits = MaximumCredits,
                EnableSmb311Preview = EnableSmb311Preview
            };
        }

        internal static OpenCifsServerSettings FromOptions(OpenCifsServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            }

            return new OpenCifsServerSettings(
                options.ServerName,
                options.BindAddress,
                options.BindPort,
                options.ShareName,
                options.SharePath,
                options.MinimumDialect,
                options.MaximumDialect,
                options.RequireSigning,
                options.RequireNtlmV2,
                options.AllowAnonymous,
                options.EnableSmb1,
                options.RequireEncryptionForSmb3,
                options.MaximumCredits,
                options.EnableSmb311Preview);
        }
    }
}
