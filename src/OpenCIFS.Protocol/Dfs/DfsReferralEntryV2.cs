namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// Bounded DFS referral version 2 entry.
    /// </summary>
    public sealed class DfsReferralEntryV2
    {
        private const ushort VersionNumberValue = 0x0002;
        private const int FixedLength = 22;
        private const ushort RootTargetServerType = 0x0001;
        private const ushort NonRootTargetServerType = 0x0000;

        /// <summary>
        /// Whether the target is a DFS root target.
        /// </summary>
        public bool IsRootTarget { get; set; }

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
        /// Target network address such as <c>\server\share\path</c>.
        /// </summary>
        public string NetworkAddress { get; set; } = string.Empty;

        internal byte[] ToByteArray()
        {
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
            writer.WriteUInt16(VersionNumberValue);
            writer.WriteUInt16(entrySize);
            writer.WriteUInt16(IsRootTarget ? RootTargetServerType : NonRootTargetServerType);
            writer.WriteUInt16(0);
            writer.WriteUInt32(0);
            writer.WriteUInt32(TimeToLive);
            writer.WriteUInt16(dfsPathOffset);
            writer.WriteUInt16(alternatePathOffset);
            writer.WriteUInt16(networkAddressOffset);
            writer.WriteBytes(dfsPathBytes);
            writer.WriteBytes(alternatePathBytes);
            writer.WriteBytes(networkAddressBytes);
            return writer.ToArray();
        }

        internal static DfsReferralEntryV2 ReadFrom(ReadOnlyMemory<byte> buffer, int offset, out int nextOffset)
        {
            if (offset < 0 || offset > buffer.Length - FixedLength)
            {
                throw new ProtocolEncodingException("The DFS referral entry offset is invalid.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(offset));
            ushort versionNumber = reader.ReadUInt16();

            if (versionNumber != VersionNumberValue)
            {
                throw new ProtocolEncodingException("The bounded DFS referral decoder only supports DFS referral entry version 2.");
            }

            ushort entrySize = reader.ReadUInt16();

            if (entrySize < FixedLength || offset + entrySize > buffer.Length)
            {
                throw new ProtocolEncodingException("The DFS referral entry size is invalid.");
            }

            ushort serverType = reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt32();
            uint timeToLive = reader.ReadUInt32();
            ushort dfsPathOffset = reader.ReadUInt16();
            ushort alternatePathOffset = reader.ReadUInt16();
            ushort networkAddressOffset = reader.ReadUInt16();
            ReadOnlyMemory<byte> entryBuffer = buffer.Slice(offset, entrySize);
            DfsReferralEntryV2 entry = new DfsReferralEntryV2
            {
                IsRootTarget = serverType == RootTargetServerType,
                TimeToLive = timeToLive,
                DfsPath = ReadNullTerminatedUnicodeString(entryBuffer, dfsPathOffset),
                DfsAlternatePath = ReadNullTerminatedUnicodeString(entryBuffer, alternatePathOffset),
                NetworkAddress = ReadNullTerminatedUnicodeString(entryBuffer, networkAddressOffset)
            };
            nextOffset = offset + entrySize;
            return entry;
        }

        private static byte[] EncodeNullTerminatedUnicode(string value)
        {
            return Encoding.Unicode.GetBytes(value + '\0');
        }

        private static string ReadNullTerminatedUnicodeString(ReadOnlyMemory<byte> buffer, int offset)
        {
            if (offset < FixedLength || offset >= buffer.Length || (offset & 1) != 0)
            {
                throw new ProtocolEncodingException("The DFS referral string offset is invalid.");
            }

            ReadOnlySpan<byte> span = buffer.Span;

            for (int index = offset; index <= span.Length - 2; index += 2)
            {
                if (span[index] == 0 && span[index + 1] == 0)
                {
                    return Encoding.Unicode.GetString(span.Slice(offset, index - offset));
                }
            }

            throw new ProtocolEncodingException("The DFS referral string was not null-terminated.");
        }
    }
}
