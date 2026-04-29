namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Client bootstrap options for OpenCIFS.
    /// </summary>
    public sealed class OpenCifsClientOptions
    {
        /// <summary>
        /// Remote host name or address.
        /// Default value: <c>127.0.0.1</c>.
        /// </summary>
        public string ServerName
        {
            get
            {
                return _ServerName;
            }
            set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(ServerName), "ServerName cannot be null or whitespace.");
                }

                _ServerName = value;
            }
        }

        /// <summary>
        /// Remote TCP port.
        /// Default value: <c>445</c>.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>65535</c>.
        /// </summary>
        public int ServerPort
        {
            get
            {
                return _ServerPort;
            }
            set
            {
                _ServerPort = Math.Clamp(value, 1, 65535);
            }
        }

        /// <summary>
        /// Minimum negotiated dialect.
        /// Default value: <see cref="SmbDialect.Smb2002" />.
        /// </summary>
        public SmbDialect MinimumDialect { get; set; } = SmbDialect.Smb2002;

        /// <summary>
        /// Maximum negotiated dialect.
        /// Default value: <see cref="SmbDialect.Smb311" />.
        /// </summary>
        public SmbDialect MaximumDialect { get; set; } = SmbDialect.Smb311;

        /// <summary>
        /// Whether signing should be required.
        /// Default value: <c>true</c>.
        /// </summary>
        public bool RequireSigning { get; set; } = true;

        /// <summary>
        /// Whether encryption should be preferred when the dialect supports it.
        /// Default value: <c>true</c>.
        /// </summary>
        public bool PreferEncryption { get; set; } = true;

        /// <summary>
        /// Connection timeout in milliseconds.
        /// Default value: <c>30000</c>.
        /// Minimum value: <c>1000</c>.
        /// Maximum value: <c>300000</c>.
        /// </summary>
        public int ConnectTimeoutMs
        {
            get
            {
                return _ConnectTimeoutMs;
            }
            set
            {
                _ConnectTimeoutMs = Math.Clamp(value, 1000, 300000);
            }
        }

        /// <summary>
        /// Validate option combinations.
        /// </summary>
        /// <exception cref="ArgumentException">Thrown when the configured dialect range is invalid.</exception>
        public void Validate()
        {
            if (MaximumDialect < MinimumDialect)
            {
                throw new ArgumentException("MaximumDialect must be greater than or equal to MinimumDialect.", nameof(MaximumDialect));
            }
        }

        private string _ServerName = "127.0.0.1";
        private int _ServerPort = 445;
        private int _ConnectTimeoutMs = 30000;
    }
}
