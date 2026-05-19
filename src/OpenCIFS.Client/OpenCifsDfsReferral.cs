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
        /// Whether the entry uses the NameList referral layout instead of a storage-target network address.
        /// </summary>
        public bool IsNameListReferral { get; set; }

        /// <summary>
        /// NameList special name returned by the server when <see cref="IsNameListReferral" /> is set.
        /// </summary>
        public string SpecialName { get; set; } = string.Empty;

        /// <summary>
        /// NameList expanded names returned by the server when <see cref="IsNameListReferral" /> is set.
        /// </summary>
        public string[] ExpandedNames
        {
            get
            {
                return _ExpandedNames;
            }
            set
            {
                _ExpandedNames = value ?? Array.Empty<string>();
            }
        }

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

        private string[] _ExpandedNames = Array.Empty<string>();
    }
}
