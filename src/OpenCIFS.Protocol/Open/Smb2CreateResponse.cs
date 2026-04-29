namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 create response payload.
    /// </summary>
    public sealed class Smb2CreateResponse
    {
        private const ushort StructureSize = 89;
        private const ushort FixedBodyLength = 88;

        /// <summary>
        /// Granted oplock level.
        /// </summary>
        public Smb2OplockLevel OplockLevel { get; set; } = Smb2OplockLevel.None;

        /// <summary>
        /// Response flags. Reserved for SMB 2.0.2.
        /// </summary>
        public byte Flags { get; set; }

        /// <summary>
        /// Action taken by the server.
        /// </summary>
        public Smb2CreateAction CreateAction { get; set; } = Smb2CreateAction.Opened;

        /// <summary>
        /// Creation time in FILETIME form.
        /// </summary>
        public ulong CreationTime { get; set; }

        /// <summary>
        /// Last-access time in FILETIME form.
        /// </summary>
        public ulong LastAccessTime { get; set; }

        /// <summary>
        /// Last-write time in FILETIME form.
        /// </summary>
        public ulong LastWriteTime { get; set; }

        /// <summary>
        /// Change time in FILETIME form.
        /// </summary>
        public ulong ChangeTime { get; set; }

        /// <summary>
        /// Allocation size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// End-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// File attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.Normal;

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Raw create-context bytes.
        /// </summary>
        public byte[] CreateContexts
        {
            get
            {
                return _CreateContexts;
            }
            set
            {
                _CreateContexts = value ?? throw new ArgumentNullException(nameof(CreateContexts), "CreateContexts cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] createContexts = CreateContexts;
            uint createContextsOffset = createContexts.Length == 0
                ? 0U
                : (uint)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte((byte)OplockLevel);
            writer.WriteByte(Flags);
            writer.WriteUInt32((uint)CreateAction);
            writer.WriteUInt64(CreationTime);
            writer.WriteUInt64(LastAccessTime);
            writer.WriteUInt64(LastWriteTime);
            writer.WriteUInt64(ChangeTime);
            writer.WriteUInt64(AllocationSize);
            writer.WriteUInt64(EndOfFile);
            writer.WriteUInt32((uint)FileAttributes);
            writer.WriteUInt32(0);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt32(createContextsOffset);
            writer.WriteUInt32((uint)createContexts.Length);
            writer.WriteBytes(createContexts);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2CreateResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 create response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 create response structure size must be 89 bytes.");
            }

            Smb2CreateResponse response = new Smb2CreateResponse
            {
                OplockLevel = (Smb2OplockLevel)reader.ReadByte(),
                Flags = reader.ReadByte(),
                CreateAction = (Smb2CreateAction)reader.ReadUInt32(),
                CreationTime = reader.ReadUInt64(),
                LastAccessTime = reader.ReadUInt64(),
                LastWriteTime = reader.ReadUInt64(),
                ChangeTime = reader.ReadUInt64(),
                AllocationSize = reader.ReadUInt64(),
                EndOfFile = reader.ReadUInt64(),
                FileAttributes = (FileAttributes)reader.ReadUInt32()
            };

            reader.Skip(4);
            response.PersistentFileId = reader.ReadUInt64();
            response.VolatileFileId = reader.ReadUInt64();
            uint createContextsOffset = reader.ReadUInt32();
            uint createContextsLength = reader.ReadUInt32();

            if (createContextsLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 create response contains trailing bytes without create contexts.");
                }

                response.CreateContexts = Array.Empty<byte>();
                return response;
            }

            if (createContextsLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 create response create-context length exceeds the supported maximum.");
            }

            int relativeCreateContextsOffset = checked((int)createContextsOffset) - ProtocolConstants.Smb2HeaderLength;
            int createContextsLengthValue = checked((int)createContextsLength);

            if (relativeCreateContextsOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 create response create-context offset is invalid.");
            }

            if (relativeCreateContextsOffset + createContextsLengthValue > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 create response create-context buffer exceeds the available payload.");
            }

            response.CreateContexts = buffer.Slice(relativeCreateContextsOffset, createContextsLengthValue).ToArray();
            return response;
        }

        private byte[] _CreateContexts = Array.Empty<byte>();
    }
}
