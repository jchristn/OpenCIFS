namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Remote share entry discovered through the OpenCIFS IPC$ / SRVSVC client path.
    /// </summary>
    public sealed class OpenCifsRemoteShareInfo
    {
        private const uint ShareTypeMask = 0x000000FF;
        private const uint ShareTypeTemporary = 0x40000000;
        private const uint ShareTypeSpecial = 0x80000000;

        /// <summary>
        /// Share name.
        /// </summary>
        public string Name { get; init; } = string.Empty;

        /// <summary>
        /// Raw SRVSVC share type value.
        /// </summary>
        public uint RawType { get; init; }

        /// <summary>
        /// Optional share remark when the remote server provides one.
        /// </summary>
        public string Remark { get; init; } = string.Empty;

        /// <summary>
        /// Optional share permission mask when detailed share information is requested.
        /// </summary>
        public uint? Permissions { get; init; }

        /// <summary>
        /// Optional maximum concurrent uses when detailed share information is requested.
        /// </summary>
        public uint? MaximumUses { get; init; }

        /// <summary>
        /// Optional current use count when detailed share information is requested.
        /// </summary>
        public uint? CurrentUses { get; init; }

        /// <summary>
        /// Optional local path reported by the remote server when detailed share information is requested.
        /// </summary>
        public string LocalPath { get; init; } = string.Empty;

        /// <summary>
        /// Whether the instance contains bounded detailed share information beyond basic enumeration fields.
        /// </summary>
        public bool HasDetailedInformation
        {
            get
            {
                return Permissions.HasValue || MaximumUses.HasValue || CurrentUses.HasValue || !string.IsNullOrWhiteSpace(LocalPath);
            }
        }

        /// <summary>
        /// Bounded normalized share-kind label.
        /// </summary>
        public string Kind
        {
            get
            {
                switch (RawType & ShareTypeMask)
                {
                    case 0:
                        return "disk";
                    case 1:
                        return "printer";
                    case 2:
                        return "device";
                    case 3:
                        return "ipc";
                    default:
                        return "unknown";
                }
            }
        }

        /// <summary>
        /// Whether the remote server marked the share as special.
        /// </summary>
        public bool IsSpecial
        {
            get
            {
                return (RawType & ShareTypeSpecial) != 0;
            }
        }

        /// <summary>
        /// Whether the remote server marked the share as temporary.
        /// </summary>
        public bool IsTemporary
        {
            get
            {
                return (RawType & ShareTypeTemporary) != 0;
            }
        }

        /// <summary>
        /// Format the share entry for console-style diagnostics.
        /// </summary>
        /// <returns>Formatted share label.</returns>
        public string ToDisplayString()
        {
            string flags = string.Empty;

            if (IsSpecial)
            {
                flags += " special";
            }

            if (IsTemporary)
            {
                flags += " temporary";
            }

            string suffix = String.IsNullOrWhiteSpace(Remark) ? string.Empty : " - " + Remark.Trim();
            return Name + " [" + Kind + flags + "]" + suffix;
        }
    }
}
