namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// SMB2 query-directory request payload.
    /// </summary>
    public sealed class Smb2QueryDirectoryRequest
    {
        private const ushort StructureSize = 33;
        private const ushort FixedBodyLength = 32;

        /// <summary>
        /// Directory information class requested by the client.
        /// </summary>
        public FileInformationClass FileInfoClass { get; set; } = FileInformationClass.DirectoryInformation;

        /// <summary>
        /// Query-directory flags.
        /// </summary>
        public Smb2QueryDirectoryFlags Flags { get; set; } = Smb2QueryDirectoryFlags.None;

        /// <summary>
        /// Optional file index used for resume semantics.
        /// </summary>
        public uint FileIndex { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Maximum response buffer length.
        /// </summary>
        public uint OutputBufferLength { get; set; }

        /// <summary>
        /// Optional search pattern.
        /// </summary>
        public string FileNamePattern
        {
            get
            {
                return _FileNamePattern;
            }
            set
            {
                _FileNamePattern = value ?? throw new ArgumentNullException(nameof(FileNamePattern), "FileNamePattern cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] fileNameBytes = FileNamePattern.Length == 0
                ? Array.Empty<byte>()
                : Encoding.Unicode.GetBytes(FileNamePattern);
            ushort fileNameOffset = fileNameBytes.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte((byte)FileInfoClass);
            writer.WriteByte((byte)Flags);
            writer.WriteUInt32(FileIndex);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt16(fileNameOffset);
            writer.WriteUInt16((ushort)fileNameBytes.Length);
            writer.WriteUInt32(OutputBufferLength);
            writer.WriteBytes(fileNameBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2QueryDirectoryRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 query-directory request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory request structure size must be 33 bytes.");
            }

            Smb2QueryDirectoryRequest request = new Smb2QueryDirectoryRequest
            {
                FileInfoClass = (FileInformationClass)reader.ReadByte(),
                Flags = (Smb2QueryDirectoryFlags)reader.ReadByte(),
                FileIndex = reader.ReadUInt32(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64()
            };
            ushort fileNameOffset = reader.ReadUInt16();
            ushort fileNameLength = reader.ReadUInt16();
            request.OutputBufferLength = reader.ReadUInt32();

            if (fileNameLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 query-directory request contains trailing bytes without a search-pattern length.");
                }

                request.FileNamePattern = string.Empty;
                return request;
            }

            if ((fileNameLength % 2) != 0)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory request search-pattern length is not valid UTF-16.");
            }

            int relativeFileNameOffset = fileNameOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativeFileNameOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory request search-pattern offset is invalid.");
            }

            if (relativeFileNameOffset + fileNameLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 query-directory request search pattern exceeds the available payload.");
            }

            request.FileNamePattern = Encoding.Unicode.GetString(buffer.Slice(relativeFileNameOffset, fileNameLength).ToArray());
            return request;
        }

        private string _FileNamePattern = string.Empty;
    }
}
