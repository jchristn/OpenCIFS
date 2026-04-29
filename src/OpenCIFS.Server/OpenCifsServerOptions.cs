namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Server bootstrap options for OpenCIFS.
    /// </summary>
    public sealed class OpenCifsServerOptions
    {
        /// <summary>
        /// Server display name.
        /// Default value: <c>OpenCIFS</c>.
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
        /// Local bind address.
        /// Default value: <c>127.0.0.1</c>.
        /// </summary>
        public string BindAddress
        {
            get
            {
                return _BindAddress;
            }
            set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(BindAddress), "BindAddress cannot be null or whitespace.");
                }

                _BindAddress = value;
            }
        }

        /// <summary>
        /// Local bind port.
        /// Default value: <c>4450</c>.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>65535</c>.
        /// </summary>
        public int BindPort
        {
            get
            {
                return _BindPort;
            }
            set
            {
                _BindPort = Math.Clamp(value, 1, 65535);
            }
        }

        /// <summary>
        /// Legacy fallback share name exposed when no explicit share registrations are provided.
        /// Default value: <c>share</c>.
        /// </summary>
        public string ShareName
        {
            get
            {
                return _ShareName;
            }
            set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(ShareName), "ShareName cannot be null or whitespace.");
                }

                _ShareName = value;
            }
        }

        /// <summary>
        /// Legacy fallback filesystem path used when no explicit share registrations are provided.
        /// Default value: <c>SampleShare</c>.
        /// </summary>
        public string SharePath
        {
            get
            {
                return _SharePath;
            }
            set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(SharePath), "SharePath cannot be null or whitespace.");
                }

                _SharePath = value;
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
        /// Whether message signing is required.
        /// Default value: <c>true</c>.
        /// </summary>
        public bool RequireSigning { get; set; } = true;

        /// <summary>
        /// Whether NTLMv2 is required.
        /// Default value: <c>true</c>.
        /// </summary>
        public bool RequireNtlmV2 { get; set; } = true;

        /// <summary>
        /// Whether anonymous access is allowed.
        /// Default value: <c>false</c>.
        /// </summary>
        public bool AllowAnonymous { get; set; } = false;

        /// <summary>
        /// Whether SMB1 is enabled.
        /// Default value: <c>false</c>.
        /// </summary>
        public bool EnableSmb1 { get; set; } = false;

        /// <summary>
        /// Whether SMB 3.x sessions should require encryption.
        /// Default value: <c>true</c>.
        /// </summary>
        public bool RequireEncryptionForSmb3 { get; set; } = true;

        /// <summary>
        /// Maximum SMB2 credits that may be granted to a client on a single connection.
        /// Default value: <c>64</c>.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>65535</c>.
        /// </summary>
        public int MaximumCredits
        {
            get
            {
                return _MaximumCredits;
            }
            set
            {
                _MaximumCredits = Math.Clamp(value, 1, UInt16.MaxValue);
            }
        }

        /// <summary>
        /// Optional request-callback surface for application-controlled operations.
        /// Default value: <c>null</c>.
        /// </summary>
        public OpenCifsServerRequestCallbacks? RequestCallbacks { get; set; }

        /// <summary>
        /// Optional diagnostic sink for server-host trace messages.
        /// Default value: <c>null</c>.
        /// </summary>
        public Action<string>? DiagnosticLogger { get; set; }

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

            if (!EnableSmb1 && MinimumDialect == SmbDialect.Cifs10)
            {
                throw new ArgumentException("MinimumDialect cannot be SMB1/CIFS when EnableSmb1 is false.", nameof(MinimumDialect));
            }
        }

        private string _ServerName = "OpenCIFS";
        private string _BindAddress = "127.0.0.1";
        private int _BindPort = 4450;
        private int _MaximumCredits = 64;
        private string _ShareName = "share";
        private string _SharePath = "SampleShare";
    }
}
