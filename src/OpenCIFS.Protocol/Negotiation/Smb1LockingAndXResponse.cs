namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_LOCKING_ANDX</c> response acknowledging the lock or unlock operation.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.32.2. The response carries WordCount=2 (AndX header only) and
    /// ByteCount=0; success or failure is conveyed through the SMB1 header status field.
    /// </remarks>
    public sealed class Smb1LockingAndXResponse
    {
        private const byte WordCountValue = 0x02;
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
        /// Serialize the LOCKING_ANDX response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.LockingAndX)
            {
                throw new ProtocolValidationException("The SMB1 LOCKING_ANDX response header command must be SMB_COM_LOCKING_ANDX.", nameof(Header));
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 LOCKING_ANDX response from its wire bytes.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1LockingAndXResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 LOCKING_ANDX response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.LockingAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_LOCKING_ANDX command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 LOCKING_ANDX response must use WordCount=2.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 LOCKING_ANDX response must use ByteCount=0.");
            }

            return new Smb1LockingAndXResponse
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.LockingAndX,
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
