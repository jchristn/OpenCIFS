namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// Bounded DFS referral version 3 or version 4 entry per MS-DFSC section 2.2.5.4.
    /// </summary>
    /// <remarks>
    /// The bounded codec only supports the path-consumer layout
    /// (<see cref="DfsReferralEntryFlags.NameListReferral" /> not set), which carries the DFS
    /// path, alternate path, and network address strings plus a 16-byte ServiceSiteGuid. The
    /// V4-specific <see cref="DfsReferralEntryFlags.TargetSetBoundary" /> bit is preserved across
    /// round-trip but does not change the wire layout. The NameList referral shape used for
    /// domain controller referrals remains backlog and is not exposed by this codec.
    /// </remarks>
    public sealed class DfsReferralEntryV3
    {
        private const int FixedLength = 34;
        private const ushort RootTargetServerType = 0x0001;
        private const ushort NonRootTargetServerType = 0x0000;

        /// <summary>
        /// Version of the entry. Must be 3 or 4. Defaults to 3.
        /// </summary>
        public ushort VersionNumber { get; set; } = 3;

        /// <summary>
        /// Whether the target is a DFS root target.
        /// </summary>
        public bool IsRootTarget { get; set; }

        /// <summary>
        /// Per-entry referral flags. The bounded codec only supports the path-consumer layout
        /// where <see cref="DfsReferralEntryFlags.NameListReferral" /> is not set.
        /// </summary>
        public DfsReferralEntryFlags ReferralEntryFlags { get; set; }

        /// <summary>
        /// Referral time-to-live, in seconds.
        /// </summary>
        public uint TimeToLive { get; set; } = 300;

        /// <summary>
        /// DFS namespace path prefix that matched the request.
        /// </summary>
        public string DfsPath { get; set; } = string.Empty;

        /// <summary>
        /// Alternate DFS path for the entry.
        /// </summary>
        public string DfsAlternatePath { get; set; } = string.Empty;

        /// <summary>
        /// Target network address such as <c>\\server\share\path</c>.
        /// </summary>
        public string NetworkAddress { get; set; } = string.Empty;

        /// <summary>
        /// NameList special name preserved by the bounded managed surface when the NameList layout is selected.
        /// </summary>
        public string SpecialName { get; set; } = string.Empty;

        /// <summary>
        /// NameList expanded names preserved by the bounded managed surface when the NameList layout is selected.
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
        /// 16-byte ServiceSiteGuid identifying the site hosting the target.
        /// </summary>
        public byte[] ServiceSiteGuid
        {
            get
            {
                return _ServiceSiteGuid;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(ServiceSiteGuid), "ServiceSiteGuid cannot be null.");
                }

                if (value.Length != 16)
                {
                    throw new ArgumentException("ServiceSiteGuid must be exactly 16 bytes.", nameof(ServiceSiteGuid));
                }

                _ServiceSiteGuid = value;
            }
        }

        internal byte[] ToByteArray()
        {
            if (VersionNumber != 3 && VersionNumber != 4)
            {
                throw new ProtocolValidationException("DFS referral entry V3 codec requires VersionNumber 3 or 4.", nameof(VersionNumber));
            }

            if ((ReferralEntryFlags & DfsReferralEntryFlags.NameListReferral) != 0)
            {
                throw new ProtocolValidationException("The bounded DFS referral V3 codec does not support the NameList referral layout.", nameof(ReferralEntryFlags));
            }

            if (string.IsNullOrWhiteSpace(DfsPath))
            {
                throw new ArgumentNullException(nameof(DfsPath), "DfsPath cannot be null or whitespace.");
            }

            if (string.IsNullOrWhiteSpace(NetworkAddress))
            {
                throw new ArgumentNullException(nameof(NetworkAddress), "NetworkAddress cannot be null or whitespace.");
            }

            string alternatePath = string.IsNullOrWhiteSpace(DfsAlternatePath) ? DfsPath : DfsAlternatePath;
            byte[] dfsPathBytes = EncodeNullTerminatedUnicode(DfsPath);
            byte[] alternatePathBytes = EncodeNullTerminatedUnicode(alternatePath);
            byte[] networkAddressBytes = EncodeNullTerminatedUnicode(NetworkAddress);
            ushort dfsPathOffset = FixedLength;
            ushort alternatePathOffset = checked((ushort)(dfsPathOffset + dfsPathBytes.Length));
            ushort networkAddressOffset = checked((ushort)(alternatePathOffset + alternatePathBytes.Length));
            ushort entrySize = checked((ushort)(networkAddressOffset + networkAddressBytes.Length));

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(VersionNumber);
            writer.WriteUInt16(entrySize);
            writer.WriteUInt16(IsRootTarget ? RootTargetServerType : NonRootTargetServerType);
            writer.WriteUInt16((ushort)ReferralEntryFlags);
            writer.WriteUInt32(TimeToLive);
            writer.WriteUInt16(dfsPathOffset);
            writer.WriteUInt16(alternatePathOffset);
            writer.WriteUInt16(networkAddressOffset);
            writer.WriteBytes(_ServiceSiteGuid);
            writer.WriteBytes(dfsPathBytes);
            writer.WriteBytes(alternatePathBytes);
            writer.WriteBytes(networkAddressBytes);
            return writer.ToArray();
        }

        internal static DfsReferralEntryV3 ReadFrom(ReadOnlyMemory<byte> buffer, int offset, out int nextOffset)
        {
            if (offset < 0 || offset > buffer.Length - FixedLength)
            {
                throw new ProtocolEncodingException("The DFS referral V3 entry offset is invalid.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(offset));
            ushort versionNumber = reader.ReadUInt16();

            if (versionNumber != 3 && versionNumber != 4)
            {
                throw new ProtocolEncodingException("The bounded DFS referral V3 decoder requires VersionNumber 3 or 4.");
            }

            ushort entrySize = reader.ReadUInt16();

            if (entrySize < FixedLength || offset + entrySize > buffer.Length)
            {
                throw new ProtocolEncodingException("The DFS referral V3 entry size is invalid.");
            }

            ushort serverType = reader.ReadUInt16();
            ushort referralFlags = reader.ReadUInt16();

            if ((referralFlags & (ushort)DfsReferralEntryFlags.NameListReferral) != 0)
            {
                throw new ProtocolEncodingException("The bounded DFS referral V3 codec does not support the NameList referral layout.");
            }

            uint timeToLive = reader.ReadUInt32();
            ushort dfsPathOffset = reader.ReadUInt16();
            ushort alternatePathOffset = reader.ReadUInt16();
            ushort networkAddressOffset = reader.ReadUInt16();
            byte[] serviceSiteGuid = reader.ReadBytes(16);
            ReadOnlyMemory<byte> entryBuffer = buffer.Slice(offset, entrySize);
            DfsReferralEntryV3 entry = new DfsReferralEntryV3
            {
                VersionNumber = versionNumber,
                IsRootTarget = serverType == RootTargetServerType,
                ReferralEntryFlags = (DfsReferralEntryFlags)referralFlags,
                TimeToLive = timeToLive,
                DfsPath = ReadNullTerminatedUnicodeString(entryBuffer, buffer, offset, dfsPathOffset, "dfs_path"),
                DfsAlternatePath = ReadNullTerminatedUnicodeString(entryBuffer, buffer, offset, alternatePathOffset, "dfs_alternate_path"),
                NetworkAddress = ReadNullTerminatedUnicodeString(entryBuffer, buffer, offset, networkAddressOffset, "network_address"),
                ServiceSiteGuid = serviceSiteGuid
            };
            nextOffset = offset + entrySize;
            return entry;
        }

        private static byte[] EncodeNullTerminatedUnicode(string value)
        {
            return Encoding.Unicode.GetBytes(value + '\0');
        }

        private static string ReadNullTerminatedUnicodeString(
            ReadOnlyMemory<byte> entryBuffer,
            ReadOnlyMemory<byte> fullBuffer,
            int entryOffset,
            int stringOffset,
            string fieldName)
        {
            if (TryReadNullTerminatedUnicodeString(entryBuffer, stringOffset, FixedLength, out string? value))
            {
                return value!;
            }

            if (TryReadNullTerminatedUnicodeString(fullBuffer, entryOffset + stringOffset, entryOffset + FixedLength, out value))
            {
                return value!;
            }

            throw new ProtocolEncodingException(
                "The DFS referral V3 string offset is invalid for " + fieldName +
                " (entry_offset=" + entryOffset + ", string_offset=" + stringOffset +
                ", entry_length=" + entryBuffer.Length + ", payload_length=" + fullBuffer.Length + ").");
        }

        private static bool TryReadNullTerminatedUnicodeString(
            ReadOnlyMemory<byte> buffer,
            int offset,
            int minimumOffset,
            out string? value)
        {
            value = null;

            if (offset < minimumOffset || offset >= buffer.Length || (offset & 1) != 0)
            {
                return false;
            }

            ReadOnlySpan<byte> span = buffer.Span;

            for (int index = offset; index <= span.Length - 2; index += 2)
            {
                if (span[index] == 0 && span[index + 1] == 0)
                {
                    value = Encoding.Unicode.GetString(span.Slice(offset, index - offset));
                    return true;
                }
            }

            return false;
        }

        private string[] _ExpandedNames = Array.Empty<string>();
        private byte[] _ServiceSiteGuid = new byte[16];
    }
}
