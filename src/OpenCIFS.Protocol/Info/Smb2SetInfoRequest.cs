namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 set-info request payload.
    /// </summary>
    public sealed class Smb2SetInfoRequest
    {
        private const ushort StructureSize = 33;
        private const ushort FixedBodyLength = 32;

        /// <summary>
        /// Type of information being set.
        /// </summary>
        public Smb2InfoType InfoType { get; set; } = Smb2InfoType.File;

        /// <summary>
        /// File information class being applied.
        /// </summary>
        public FileInformationClass FileInfoClass { get; set; } = FileInformationClass.BasicInformation;

        /// <summary>
        /// Additional information flags.
        /// </summary>
        public uint AdditionalInformation { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Buffer bytes.
        /// </summary>
        public byte[] Buffer
        {
            get
            {
                return _Buffer;
            }
            set
            {
                _Buffer = value ?? throw new ArgumentNullException(nameof(Buffer), "Buffer cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            ushort bufferOffset = Buffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte((byte)InfoType);
            writer.WriteByte((byte)FileInfoClass);
            writer.WriteUInt32((uint)Buffer.Length);
            writer.WriteUInt16(bufferOffset);
            writer.WriteUInt16(0);
            writer.WriteUInt32(AdditionalInformation);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteBytes(Buffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2SetInfoRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 set-info request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 set-info request structure size must be 33 bytes.");
            }

            Smb2SetInfoRequest request = new Smb2SetInfoRequest
            {
                InfoType = (Smb2InfoType)reader.ReadByte(),
                FileInfoClass = (FileInformationClass)reader.ReadByte()
            };
            uint bufferLength = reader.ReadUInt32();
            ushort bufferOffset = reader.ReadUInt16();
            reader.Skip(2);
            request.AdditionalInformation = reader.ReadUInt32();
            request.PersistentFileId = reader.ReadUInt64();
            request.VolatileFileId = reader.ReadUInt64();

            if (bufferLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 set-info request contains trailing bytes without a buffer length.");
                }

                request.Buffer = Array.Empty<byte>();
                return request;
            }

            if (bufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 set-info request buffer exceeds the supported maximum.");
            }

            int relativeBufferOffset = bufferOffset - ProtocolConstants.Smb2HeaderLength;
            int bufferLengthValue = checked((int)bufferLength);

            if (relativeBufferOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 set-info request buffer offset is invalid.");
            }

            if (relativeBufferOffset + bufferLengthValue > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 set-info request buffer exceeds the available payload.");
            }

            request.Buffer = buffer.Slice(relativeBufferOffset, bufferLengthValue).ToArray();
            return request;
        }

        private byte[] _Buffer = Array.Empty<byte>();
    }
}
