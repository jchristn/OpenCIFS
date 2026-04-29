namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 write request payload.
    /// </summary>
    public sealed class Smb2WriteRequest
    {
        private const ushort StructureSize = 49;
        private const ushort FixedBodyLength = 48;

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
        /// Channel identifier. Reserved for SMB 2.0.2.
        /// </summary>
        public uint Channel { get; set; }

        /// <summary>
        /// Remaining RDMA bytes. Reserved for SMB 2.0.2.
        /// </summary>
        public uint RemainingBytes { get; set; }

        /// <summary>
        /// Write flags.
        /// </summary>
        public Smb2WriteFlags Flags { get; set; } = Smb2WriteFlags.None;

        /// <summary>
        /// Data buffer to write.
        /// </summary>
        public byte[] DataBuffer
        {
            get
            {
                return _DataBuffer;
            }
            set
            {
                _DataBuffer = value ?? throw new ArgumentNullException(nameof(DataBuffer), "DataBuffer cannot be null.");
            }
        }

        /// <summary>
        /// Optional write-channel information.
        /// </summary>
        public byte[] WriteChannelInfo
        {
            get
            {
                return _WriteChannelInfo;
            }
            set
            {
                _WriteChannelInfo = value ?? throw new ArgumentNullException(nameof(WriteChannelInfo), "WriteChannelInfo cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            ushort dataOffset = DataBuffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);
            ushort writeChannelInfoOffset = WriteChannelInfo.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength + DataBuffer.Length);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(dataOffset);
            writer.WriteUInt32((uint)DataBuffer.Length);
            writer.WriteUInt64(Offset);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt32(Channel);
            writer.WriteUInt32(RemainingBytes);
            writer.WriteUInt16(writeChannelInfoOffset);
            writer.WriteUInt16((ushort)WriteChannelInfo.Length);
            writer.WriteUInt32((uint)Flags);
            writer.WriteBytes(DataBuffer);
            writer.WriteBytes(WriteChannelInfo);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2WriteRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 write request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 write request structure size must be 49 bytes.");
            }

            ushort dataOffset = reader.ReadUInt16();
            uint dataLength = reader.ReadUInt32();
            Smb2WriteRequest request = new Smb2WriteRequest
            {
                Offset = reader.ReadUInt64(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64(),
                Channel = reader.ReadUInt32(),
                RemainingBytes = reader.ReadUInt32()
            };

            ushort writeChannelInfoOffset = reader.ReadUInt16();
            ushort writeChannelInfoLength = reader.ReadUInt16();
            request.Flags = (Smb2WriteFlags)reader.ReadUInt32();

            if (dataLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 write request data length exceeds the supported maximum.");
            }

            int dataLengthValue = checked((int)dataLength);

            if (dataLengthValue == 0)
            {
                request.DataBuffer = Array.Empty<byte>();
            }
            else
            {
                int relativeDataOffset = dataOffset - ProtocolConstants.Smb2HeaderLength;

                if (relativeDataOffset < FixedBodyLength)
                {
                    throw new ProtocolEncodingException("The SMB2 write request data offset is invalid.");
                }

                if (relativeDataOffset + dataLengthValue > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB2 write request data buffer exceeds the available payload.");
                }

                request.DataBuffer = buffer.Slice(relativeDataOffset, dataLengthValue).ToArray();
            }

            if (writeChannelInfoLength == 0)
            {
                request.WriteChannelInfo = Array.Empty<byte>();
                return request;
            }

            int relativeWriteChannelInfoOffset = writeChannelInfoOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativeWriteChannelInfoOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 write request channel-info offset is invalid.");
            }

            if (relativeWriteChannelInfoOffset + writeChannelInfoLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 write request channel-info buffer exceeds the available payload.");
            }

            request.WriteChannelInfo = buffer.Slice(relativeWriteChannelInfoOffset, writeChannelInfoLength).ToArray();
            return request;
        }

        private byte[] _DataBuffer = Array.Empty<byte>();
        private byte[] _WriteChannelInfo = Array.Empty<byte>();
    }
}
