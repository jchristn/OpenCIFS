namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_NT_CREATE_ANDX</c> response in the extended WordCount=34 shape.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.64.2. Returned for both file and directory opens; the response carries
    /// the assigned FID, NT-style timestamps, allocation/EOF sizes, resource-type discriminator,
    /// pipe status (only meaningful for named-pipe opens), and a directory flag. The bounded codec
    /// emits ByteCount=0 with no payload, which matches the standard non-extended NT response shape.
    /// </remarks>
    public sealed class Smb1NtCreateAndXResponse
    {
        private const byte WordCountValue = 0x22;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;

        /// <summary>
        /// SMB1 response header.
        /// </summary>
        public Smb1Header Header
        {
            get
            {
                return _Header;
            }
            set
            {
                _Header = value ?? throw new ArgumentNullException(nameof(Header), "Header cannot be null.");
            }
        }

        /// <summary>
        /// Trailing AndX command code, or <c>0xFF</c> when no further command follows.
        /// </summary>
        public byte AndXCommand { get; set; } = AndXNoFurtherCommands;

        /// <summary>
        /// AndX offset relative to the SMB header start, in bytes.
        /// </summary>
        public ushort AndXOffset { get; set; }

        /// <summary>
        /// Granted oplock level. 0 = none, 1 = exclusive, 2 = batch, 3 = level II.
        /// </summary>
        public byte OplockLevel { get; set; }

        /// <summary>
        /// Server-assigned SMB1 file identifier for subsequent file-I/O commands.
        /// </summary>
        public ushort FileId { get; set; }

        /// <summary>
        /// Disposition action that the server actually performed (e.g. FILE_OPENED, FILE_CREATED).
        /// </summary>
        public uint CreateDisposition { get; set; }

        /// <summary>
        /// Creation time as a Windows FILETIME (100ns ticks since 1601-01-01 UTC).
        /// </summary>
        public long CreateTime { get; set; }

        /// <summary>
        /// Last-access time as a Windows FILETIME.
        /// </summary>
        public long LastAccessTime { get; set; }

        /// <summary>
        /// Last-write time as a Windows FILETIME.
        /// </summary>
        public long LastWriteTime { get; set; }

        /// <summary>
        /// Last-change time as a Windows FILETIME (server-side metadata change).
        /// </summary>
        public long LastChangeTime { get; set; }

        /// <summary>
        /// File attributes returned to the caller.
        /// </summary>
        public uint ExtFileAttributes { get; set; }

        /// <summary>
        /// Allocation size, in bytes.
        /// </summary>
        public long AllocationSize { get; set; }

        /// <summary>
        /// End-of-file offset, in bytes.
        /// </summary>
        public long EndOfFile { get; set; }

        /// <summary>
        /// Resource type discriminator (file, named pipe, message-mode pipe, comm device).
        /// </summary>
        public ushort ResourceType { get; set; }

        /// <summary>
        /// Named-pipe status. Zero for file opens.
        /// </summary>
        public ushort NMPipeStatus { get; set; }

        /// <summary>
        /// 1 when the open refers to a directory, 0 otherwise.
        /// </summary>
        public byte Directory { get; set; }

        /// <summary>
        /// Serialize the NT_CREATE_ANDX response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.NtCreateAndX)
            {
                throw new ProtocolValidationException("The SMB1 NT_CREATE_ANDX response header command must be SMB_COM_NT_CREATE_ANDX.", nameof(Header));
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteByte(OplockLevel);
            writer.WriteUInt16(FileId);
            writer.WriteUInt32(CreateDisposition);
            writer.WriteUInt64(unchecked((ulong)CreateTime));
            writer.WriteUInt64(unchecked((ulong)LastAccessTime));
            writer.WriteUInt64(unchecked((ulong)LastWriteTime));
            writer.WriteUInt64(unchecked((ulong)LastChangeTime));
            writer.WriteUInt32(ExtFileAttributes);
            writer.WriteUInt64(unchecked((ulong)AllocationSize));
            writer.WriteUInt64(unchecked((ulong)EndOfFile));
            writer.WriteUInt16(ResourceType);
            writer.WriteUInt16(NMPipeStatus);
            writer.WriteByte(Directory);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 NT_CREATE_ANDX response from its wire bytes.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1NtCreateAndXResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 NT_CREATE_ANDX response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.NtCreateAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_NT_CREATE_ANDX command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX response must use WordCount=34.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            byte oplockLevel = reader.ReadByte();
            ushort fileId = reader.ReadUInt16();
            uint createDisposition = reader.ReadUInt32();
            long createTime = unchecked((long)reader.ReadUInt64());
            long lastAccessTime = unchecked((long)reader.ReadUInt64());
            long lastWriteTime = unchecked((long)reader.ReadUInt64());
            long lastChangeTime = unchecked((long)reader.ReadUInt64());
            uint extFileAttributes = reader.ReadUInt32();
            long allocationSize = unchecked((long)reader.ReadUInt64());
            long endOfFile = unchecked((long)reader.ReadUInt64());
            ushort resourceType = reader.ReadUInt16();
            ushort nmPipeStatus = reader.ReadUInt16();
            byte directory = reader.ReadByte();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX response must use ByteCount=0.");
            }

            return new Smb1NtCreateAndXResponse
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                OplockLevel = oplockLevel,
                FileId = fileId,
                CreateDisposition = createDisposition,
                CreateTime = createTime,
                LastAccessTime = lastAccessTime,
                LastWriteTime = lastWriteTime,
                LastChangeTime = lastChangeTime,
                ExtFileAttributes = extFileAttributes,
                AllocationSize = allocationSize,
                EndOfFile = endOfFile,
                ResourceType = resourceType,
                NMPipeStatus = nmPipeStatus,
                Directory = directory
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.NtCreateAndX,
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
