namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Bounded server-side DFS referral configuration.
    /// </summary>
    public sealed class OpenCifsServerDfsReferral
    {
        /// <summary>
        /// Namespace share exposed by the server.
        /// </summary>
        public string NamespaceShareName
        {
            get
            {
                return _NamespaceShareName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(NamespaceShareName), "NamespaceShareName cannot be null or whitespace.");
                }

                _NamespaceShareName = value;
            }
        }

        /// <summary>
        /// Relative namespace path prefix within <see cref="NamespaceShareName" />. Empty or <c>/</c> maps the namespace root.
        /// </summary>
        public string NamespacePath { get; set; } = string.Empty;

        /// <summary>
        /// Target server name to return in the referral.
        /// </summary>
        public string TargetServerName
        {
            get
            {
                return _TargetServerName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(TargetServerName), "TargetServerName cannot be null or whitespace.");
                }

                _TargetServerName = value;
            }
        }

        /// <summary>
        /// Target share name returned in the referral.
        /// </summary>
        public string TargetShareName
        {
            get
            {
                return _TargetShareName;
            }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(TargetShareName), "TargetShareName cannot be null or whitespace.");
                }

                _TargetShareName = value;
            }
        }

        /// <summary>
        /// Relative target path beneath <see cref="TargetShareName" />.
        /// </summary>
        public string TargetPath { get; set; } = string.Empty;

        /// <summary>
        /// Referral time-to-live, in seconds.
        /// </summary>
        public uint TimeToLiveSeconds { get; set; } = 300;

        /// <summary>
        /// Validate the referral.
        /// </summary>
        public void Validate()
        {
            _ = NamespaceShareName;
            _ = TargetServerName;
            _ = TargetShareName;

            if (TimeToLiveSeconds == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(TimeToLiveSeconds), "TimeToLiveSeconds must be greater than zero.");
            }
        }

        internal OpenCifsServerDfsReferral Clone()
        {
            Validate();
            return new OpenCifsServerDfsReferral
            {
                NamespaceShareName = NamespaceShareName,
                NamespacePath = NamespacePath,
                TargetServerName = TargetServerName,
                TargetShareName = TargetShareName,
                TargetPath = TargetPath,
                TimeToLiveSeconds = TimeToLiveSeconds
            };
        }

        private string _NamespaceShareName = "share";
        private string _TargetServerName = "localhost";
        private string _TargetShareName = "share";
    }
}
