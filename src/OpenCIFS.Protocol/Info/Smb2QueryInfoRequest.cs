namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 query-info request payload.
    /// </summary>
    public sealed class Smb2QueryInfoRequest
    {
        private const ushort StructureSize = 41;
        private const ushort FixedBodyLength = 40;

        /// <summary>
        /// Type of information being queried.
        /// </summary>
        public Smb2InfoType InfoType { get; set; } = Smb2InfoType.File;

        /// <summary>
        /// File information class being queried.
        /// </summary>
        public FileInformationClass FileInfoClass { get; set; } = FileInformationClass.BasicInformation;

        /// <summary>
        /// Maximum output buffer length.
        /// </summary>
        public uint OutputBufferLength { get; set; }

        /// <summary>
        /// Additional information flags.
        /// </summary>
        public uint AdditionalInformation { get; set; }

        /// <summary>
        /// Query flags.
        /// </summary>
        public uint Flags { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Optional input buffer.
        /// </summary>
        public byte[] InputBuffer
        {
            get
            {
                return _InputBuffer;
            }
            set
            {
                _InputBuffer = value ?? throw new ArgumentNullException(nameof(InputBuffer), "InputBuffer cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            ushort inputBufferOffset = InputBuffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte((byte)InfoType);
            writer.WriteByte((byte)FileInfoClass);
            writer.WriteUInt32(OutputBufferLength);
            writer.WriteUInt16(inputBufferOffset);
            writer.WriteUInt16(0);
            writer.WriteUInt32((uint)InputBuffer.Length);
            writer.WriteUInt32(AdditionalInformation);
            writer.WriteUInt32(Flags);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteBytes(InputBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2QueryInfoRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 query-info request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 query-info request structure size must be 41 bytes.");
            }

            Smb2QueryInfoRequest request = new Smb2QueryInfoRequest
            {
                InfoType = (Smb2InfoType)reader.ReadByte(),
                FileInfoClass = (FileInformationClass)reader.ReadByte(),
                OutputBufferLength = reader.ReadUInt32()
            };
            ushort inputBufferOffset = reader.ReadUInt16();
            reader.Skip(2);
            uint inputBufferLength = reader.ReadUInt32();
            request.AdditionalInformation = reader.ReadUInt32();
            request.Flags = reader.ReadUInt32();
            request.PersistentFileId = reader.ReadUInt64();
            request.VolatileFileId = reader.ReadUInt64();

            if (inputBufferLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 query-info request contains trailing bytes without an input buffer length.");
                }

                request.InputBuffer = Array.Empty<byte>();
                return request;
            }

            if (inputBufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 query-info request input buffer exceeds the supported maximum.");
            }

            int relativeInputBufferOffset = inputBufferOffset - ProtocolConstants.Smb2HeaderLength;
            int inputBufferLengthValue = checked((int)inputBufferLength);

            if (relativeInputBufferOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 query-info request input-buffer offset is invalid.");
            }

            if (relativeInputBufferOffset + inputBufferLengthValue > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 query-info request input buffer exceeds the available payload.");
            }

            request.InputBuffer = buffer.Slice(relativeInputBufferOffset, inputBufferLengthValue).ToArray();
            return request;
        }

        private byte[] _InputBuffer = Array.Empty<byte>();
    }
}
