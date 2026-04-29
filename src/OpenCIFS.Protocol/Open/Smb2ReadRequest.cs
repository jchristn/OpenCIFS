namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 read request payload.
    /// </summary>
    public sealed class Smb2ReadRequest
    {
        private const ushort StructureSize = 49;
        private const ushort FixedBodyLength = 48;

        /// <summary>
        /// Read length.
        /// </summary>
        public uint Length { get; set; }

        /// <summary>
        /// Byte offset within the file.
        /// </summary>
        public ulong Offset { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Minimum byte count for success.
        /// </summary>
        public uint MinimumCount { get; set; }

        /// <summary>
        /// Channel identifier. Reserved for SMB 2.0.2.
        /// </summary>
        public uint Channel { get; set; }

        /// <summary>
        /// Remaining RDMA bytes. Reserved for SMB 2.0.2.
        /// </summary>
        public uint RemainingBytes { get; set; }

        /// <summary>
        /// Optional channel-info buffer.
        /// </summary>
        public byte[] ReadChannelInfo
        {
            get
            {
                return _ReadChannelInfo;
            }
            set
            {
                _ReadChannelInfo = value ?? throw new ArgumentNullException(nameof(ReadChannelInfo), "ReadChannelInfo cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            ushort channelInfoOffset = ReadChannelInfo.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte(0x50);
            writer.WriteByte(0);
            writer.WriteUInt32(Length);
            writer.WriteUInt64(Offset);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt32(MinimumCount);
            writer.WriteUInt32(Channel);
            writer.WriteUInt32(RemainingBytes);
            writer.WriteUInt16(channelInfoOffset);
            writer.WriteUInt16((ushort)ReadChannelInfo.Length);
            if (ReadChannelInfo.Length == 0)
            {
                writer.WriteByte(0);
            }
            else
            {
                writer.WriteBytes(ReadChannelInfo);
            }
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2ReadRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 read request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 read request structure size must be 49 bytes.");
            }

            reader.Skip(1);
            reader.Skip(1);
            Smb2ReadRequest request = new Smb2ReadRequest
            {
                Length = reader.ReadUInt32(),
                Offset = reader.ReadUInt64(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64(),
                MinimumCount = reader.ReadUInt32(),
                Channel = reader.ReadUInt32(),
                RemainingBytes = reader.ReadUInt32()
            };

            ushort readChannelInfoOffset = reader.ReadUInt16();
            ushort readChannelInfoLength = reader.ReadUInt16();

            if (readChannelInfoLength == 0)
            {
                if (reader.RemainingBytes == 0)
                {
                    request.ReadChannelInfo = Array.Empty<byte>();
                    return request;
                }

                if (reader.RemainingBytes != 1 || reader.ReadByte() != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 read request contains trailing bytes without channel info.");
                }

                request.ReadChannelInfo = Array.Empty<byte>();
                return request;
            }

            int relativeReadChannelInfoOffset = readChannelInfoOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativeReadChannelInfoOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 read request channel-info offset is invalid.");
            }

            if (relativeReadChannelInfoOffset + readChannelInfoLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 read request channel-info buffer exceeds the available payload.");
            }

            request.ReadChannelInfo = buffer.Slice(relativeReadChannelInfoOffset, readChannelInfoLength).ToArray();
            return request;
        }

        private byte[] _ReadChannelInfo = Array.Empty<byte>();
    }
}
