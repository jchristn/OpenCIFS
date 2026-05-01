namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Builder for the primary OpenCIFS client happy-path surface.
    /// </summary>
    public sealed class OpenCifsClientBuilder
    {
        /// <summary>
        /// Set the remote host name or address.
        /// </summary>
        /// <param name="serverName">Remote host name or address.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithServer(string serverName)
        {
            if (string.IsNullOrWhiteSpace(serverName))
            {
                throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null or whitespace.");
            }

            _ServerName = serverName;
            return this;
        }

        /// <summary>
        /// Set the remote host name or address and direct-TCP port.
        /// </summary>
        /// <param name="serverName">Remote host name or address.</param>
        /// <param name="serverPort">Remote direct-TCP port.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithServer(string serverName, int serverPort)
        {
            return WithServer(serverName).WithPort(serverPort);
        }

        /// <summary>
        /// Set the remote direct-TCP port.
        /// </summary>
        /// <param name="serverPort">Remote direct-TCP port.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithPort(int serverPort)
        {
            _ServerPort = Math.Clamp(serverPort, 1, 65535);
            return this;
        }

        /// <summary>
        /// Set the supported dialect range.
        /// </summary>
        /// <param name="minimumDialect">Minimum negotiated dialect.</param>
        /// <param name="maximumDialect">Maximum negotiated dialect.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithDialectRange(SmbDialect minimumDialect, SmbDialect maximumDialect)
        {
            _MinimumDialect = minimumDialect;
            _MaximumDialect = maximumDialect;
            return this;
        }

        /// <summary>
        /// Set whether signing is required.
        /// </summary>
        /// <param name="requireSigning">Whether signing is required.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithSigningRequired(bool requireSigning = true)
        {
            _RequireSigning = requireSigning;
            return this;
        }

        /// <summary>
        /// Set whether encryption should be preferred when supported.
        /// </summary>
        /// <param name="preferEncryption">Whether encryption should be preferred.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithPreferredEncryption(bool preferEncryption = true)
        {
            _PreferEncryption = preferEncryption;
            return this;
        }

        /// <summary>
        /// Set the connection timeout in milliseconds.
        /// </summary>
        /// <param name="connectTimeoutMs">Connection timeout in milliseconds.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsClientBuilder WithConnectTimeoutMs(int connectTimeoutMs)
        {
            _ConnectTimeoutMs = Math.Clamp(connectTimeoutMs, 1000, 300000);
            return this;
        }

        /// <summary>
        /// Enable the bounded SMB 3.1.1 preview slice on the negotiate path.
        /// When enabled, the client advertises <see cref="SmbDialect.Smb311" /> and emits typed
        /// SMB 3.1.1 negotiate-context entries (preauth integrity, signing, encryption).
        /// </summary>
        /// <param name="enableSmb311Preview">Whether the SMB 3.1.1 preview is enabled.</param>
        /// <returns>The current builder.</returns>
        /// <remarks>
        /// SMB 3.1.1 negotiation succeeds end-to-end only when the peer also opts into the preview.
        /// When the peer is an existing SMB 2.x / 3.0.2 server, the existing tolerance behavior selects
        /// the highest mutually supported dialect.
        /// </remarks>
        public OpenCifsClientBuilder WithSmb311Preview(bool enableSmb311Preview = true)
        {
            _EnableSmb311Preview = enableSmb311Preview;
            return this;
        }

        /// <summary>
        /// Build immutable validated client settings.
        /// </summary>
        /// <returns>Immutable validated client settings.</returns>
        public OpenCifsClientSettings BuildSettings()
        {
            return new OpenCifsClientSettings(
                _ServerName,
                _ServerPort,
                _MinimumDialect,
                _MaximumDialect,
                _RequireSigning,
                _PreferEncryption,
                _ConnectTimeoutMs,
                _EnableSmb311Preview);
        }

        /// <summary>
        /// Build the primary OpenCIFS client surface.
        /// </summary>
        /// <returns>The configured OpenCIFS client.</returns>
        public OpenCifsClient Build()
        {
            return new OpenCifsClient(BuildSettings());
        }

        private string _ServerName = "127.0.0.1";
        private int _ServerPort = 445;
        private SmbDialect _MinimumDialect = SmbDialect.Smb2002;
        private SmbDialect _MaximumDialect = SmbDialect.Smb311;
        private bool _RequireSigning = true;
        private bool _PreferEncryption = true;
        private int _ConnectTimeoutMs = 30000;
        private bool _EnableSmb311Preview = false;
    }
}
