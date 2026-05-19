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
        /// Optional site name associated with the referral target.
        /// </summary>
        public string SiteName { get; set; } = string.Empty;

        /// <summary>
        /// Whether the referral uses the NameList layout rather than a storage-target network address.
        /// </summary>
        public bool IsNameListReferral { get; set; }

        /// <summary>
        /// NameList special name returned when <see cref="IsNameListReferral" /> is enabled.
        /// </summary>
        public string SpecialName { get; set; } = string.Empty;

        /// <summary>
        /// NameList expanded names returned when <see cref="IsNameListReferral" /> is enabled.
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
        /// Referral time-to-live, in seconds.
        /// </summary>
        public uint TimeToLiveSeconds { get; set; } = 300;

        /// <summary>
        /// Validate the referral.
        /// </summary>
        public void Validate()
        {
            _ = NamespaceShareName;

            if (TimeToLiveSeconds == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(TimeToLiveSeconds), "TimeToLiveSeconds must be greater than zero.");
            }

            if (IsNameListReferral)
            {
                return;
            }

            _ = TargetServerName;
            _ = TargetShareName;
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
                SiteName = SiteName,
                IsNameListReferral = IsNameListReferral,
                SpecialName = SpecialName,
                ExpandedNames = CloneExpandedNames(ExpandedNames),
                TimeToLiveSeconds = TimeToLiveSeconds
            };
        }

        internal bool IsEquivalentTo(OpenCifsServerDfsReferral other)
        {
            if (other == null)
            {
                return false;
            }

            if (!StringComparer.OrdinalIgnoreCase.Equals(NamespaceShareName, other.NamespaceShareName) ||
                !StringComparer.OrdinalIgnoreCase.Equals(NormalizePath(NamespacePath), NormalizePath(other.NamespacePath)) ||
                TimeToLiveSeconds != other.TimeToLiveSeconds ||
                IsNameListReferral != other.IsNameListReferral)
            {
                return false;
            }

            if (IsNameListReferral)
            {
                return StringComparer.OrdinalIgnoreCase.Equals(SpecialName, other.SpecialName) &&
                    ExpandedNamesAreEquivalent(ExpandedNames, other.ExpandedNames);
            }

            return StringComparer.OrdinalIgnoreCase.Equals(TargetServerName, other.TargetServerName) &&
                StringComparer.OrdinalIgnoreCase.Equals(TargetShareName, other.TargetShareName) &&
                StringComparer.OrdinalIgnoreCase.Equals(NormalizePath(TargetPath), NormalizePath(other.TargetPath)) &&
                StringComparer.OrdinalIgnoreCase.Equals(SiteName, other.SiteName);
        }

        private static string NormalizePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path == "/" || path == "\\")
            {
                return string.Empty;
            }

            return path.Trim().Replace('/', '\\').Trim('\\');
        }

        private static string[] CloneExpandedNames(string[] expandedNames)
        {
            if (expandedNames == null)
            {
                return Array.Empty<string>();
            }

            string[] clone = new string[expandedNames.Length];

            for (int index = 0; index < expandedNames.Length; index++)
            {
                clone[index] = expandedNames[index];
            }

            return clone;
        }

        private static bool ExpandedNamesAreEquivalent(string[] left, string[] right)
        {
            string[] effectiveLeft = left ?? Array.Empty<string>();
            string[] effectiveRight = right ?? Array.Empty<string>();

            if (effectiveLeft.Length != effectiveRight.Length)
            {
                return false;
            }

            for (int index = 0; index < effectiveLeft.Length; index++)
            {
                if (!StringComparer.OrdinalIgnoreCase.Equals(effectiveLeft[index], effectiveRight[index]))
                {
                    return false;
                }
            }

            return true;
        }

        private string _NamespaceShareName = "share";
        private string _TargetServerName = "localhost";
        private string _TargetShareName = "share";
        private string[] _ExpandedNames = Array.Empty<string>();
    }
}
