namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_NT_CREATE_ANDX</c> request used to open or create a file or directory.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.64.1. The bounded codec only supports the SMB 3.1.1-era Unicode strings
    /// convention (<see cref="Smb1HeaderFlags2.Unicode" /> set on the carrying header) for the file
    /// name. The 1-byte alignment pad before the Unicode name is computed against the carrying
    /// header position so the trailing string starts on a 2-byte boundary.
    /// </remarks>
    public sealed class Smb1NtCreateAndXRequest
    {
        private const byte WordCountValue = 0x18;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;
        private static readonly int DataSectionStartOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

        /// <summary>
        /// SMB1 request header.
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
        /// NT_CREATE_ANDX flags (e.g. request opportunistic lock, request batch oplock, target is a directory).
        /// </summary>
        public uint Flags { get; set; }

        /// <summary>
        /// Root directory handle, or 0 when the file name is interpreted relative to the tree root.
        /// </summary>
        public uint RootDirectoryFileId { get; set; }

        /// <summary>
        /// Desired access mask (NT-style ACCESS_MASK).
        /// </summary>
        public uint DesiredAccess { get; set; }

        /// <summary>
        /// File allocation size hint when creating new files. Ignored for opens.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// File attributes for create operations.
        /// </summary>
        public uint ExtFileAttributes { get; set; }

        /// <summary>
        /// Share-access mask describing how concurrent opens may overlap.
        /// </summary>
        public uint ShareAccess { get; set; }

        /// <summary>
        /// Create disposition (e.g. FILE_OPEN, FILE_CREATE, FILE_OVERWRITE_IF) per MS-FSCC.
        /// </summary>
        public uint CreateDisposition { get; set; }

        /// <summary>
        /// Create options (e.g. FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_DELETE_ON_CLOSE).
        /// </summary>
        public uint CreateOptions { get; set; }

        /// <summary>
        /// Impersonation level requested for the open.
        /// </summary>
        public uint ImpersonationLevel { get; set; } = 0x00000002U;

        /// <summary>
        /// Bitwise security flags (CONTEXT_TRACKING, EFFECTIVE_ONLY).
        /// </summary>
        public byte SecurityFlags { get; set; }

        /// <summary>
        /// File name relative to the tree root or to <see cref="RootDirectoryFileId" /> when set.
        /// </summary>
        public string FileName
        {
            get
            {
                return _FileName;
            }
            set
            {
                _FileName = value ?? throw new ArgumentNullException(nameof(FileName), "FileName cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the NT_CREATE_ANDX request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            EnsureUnicodeShape();
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.NtCreateAndX)
            {
                throw new ProtocolValidationException("The SMB1 NT_CREATE_ANDX request header command must be SMB_COM_NT_CREATE_ANDX.", nameof(Header));
            }

            byte[] fileNameBytes = EncodeUnicodeNullTerminatedString(FileName);
            int padLength = ((DataSectionStartOffset) & 1) == 0 ? 0 : 1;
            int byteCount = padLength + fileNameBytes.Length;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(FileName), "SMB1 NT_CREATE_ANDX request payload exceeds the 16-bit ByteCount field.");
            }

            int nameLength = fileNameBytes.Length - 2;

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteByte(0);
            writer.WriteUInt16((ushort)nameLength);
            writer.WriteUInt32(Flags);
            writer.WriteUInt32(RootDirectoryFileId);
            writer.WriteUInt32(DesiredAccess);
            writer.WriteUInt64(AllocationSize);
            writer.WriteUInt32(ExtFileAttributes);
            writer.WriteUInt32(ShareAccess);
            writer.WriteUInt32(CreateDisposition);
            writer.WriteUInt32(CreateOptions);
            writer.WriteUInt32(ImpersonationLevel);
            writer.WriteByte(SecurityFlags);
            writer.WriteUInt16((ushort)byteCount);

            for (int index = 0; index < padLength; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(fileNameBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 NT_CREATE_ANDX request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1NtCreateAndXRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 NT_CREATE_ANDX request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.NtCreateAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_NT_CREATE_ANDX command.");
            }

            if ((header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolEncodingException("The bounded SMB1 NT_CREATE_ANDX codec only supports Unicode strings.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX request must use WordCount=24.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            reader.ReadByte();
            ushort nameLength = reader.ReadUInt16();
            uint flags = reader.ReadUInt32();
            uint rootDirectoryFileId = reader.ReadUInt32();
            uint desiredAccess = reader.ReadUInt32();
            ulong allocationSize = reader.ReadUInt64();
            uint extFileAttributes = reader.ReadUInt32();
            uint shareAccess = reader.ReadUInt32();
            uint createDisposition = reader.ReadUInt32();
            uint createOptions = reader.ReadUInt32();
            uint impersonationLevel = reader.ReadUInt32();
            byte securityFlags = reader.ReadByte();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX request ByteCount does not match the remaining payload length.");
            }

            int padLength = ((DataSectionStartOffset) & 1) == 0 ? 0 : 1;

            if (padLength > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX request payload is missing the Unicode alignment pad.");
            }

            reader.Skip(padLength);

            int unicodeNameBytes = nameLength + 2;

            if (unicodeNameBytes > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX request name length exceeds the remaining payload.");
            }

            byte[] nameBuffer = reader.ReadBytes(unicodeNameBytes);

            if (nameBuffer[unicodeNameBytes - 1] != 0 || nameBuffer[unicodeNameBytes - 2] != 0)
            {
                throw new ProtocolEncodingException("The SMB1 NT_CREATE_ANDX request file name is not null-terminated.");
            }

            string fileName = Encoding.Unicode.GetString(nameBuffer, 0, unicodeNameBytes - 2);

            return new Smb1NtCreateAndXRequest
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                Flags = flags,
                RootDirectoryFileId = rootDirectoryFileId,
                DesiredAccess = desiredAccess,
                AllocationSize = allocationSize,
                ExtFileAttributes = extFileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                ImpersonationLevel = impersonationLevel,
                SecurityFlags = securityFlags,
                FileName = fileName
            };
        }

        private void EnsureUnicodeShape()
        {
            if ((Header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolValidationException("The bounded SMB1 NT_CREATE_ANDX codec only supports Unicode strings.", nameof(Header));
            }
        }

        private static byte[] EncodeUnicodeNullTerminatedString(string value)
        {
            byte[] textBytes = Encoding.Unicode.GetBytes(value);
            byte[] result = new byte[textBytes.Length + 2];
            Buffer.BlockCopy(textBytes, 0, result, 0, textBytes.Length);
            return result;
        }

        private string _FileName = string.Empty;
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.NtCreateAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
