namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_LOGOFF_ANDX</c> request and response.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.54.2. The request and response carry the same WordCount=2 AndX shape
    /// with no buffer payload. Used by both client (request) and server (response) sides of the
    /// session-teardown flow.
    /// </remarks>
    public sealed class Smb1LogoffAndX
    {
        private const byte WordCountValue = 0x02;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;

        /// <summary>
        /// SMB1 header.
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
        /// Serialize the LOGOFF_ANDX message to its SMB1 wire format.
        /// </summary>
        /// <returns>Message bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.LogoffAndX)
            {
                throw new ProtocolValidationException("The SMB1 LOGOFF_ANDX header command must be SMB_COM_LOGOFF_ANDX.", nameof(Header));
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
        /// Parse an SMB1 LOGOFF_ANDX message from its wire bytes.
        /// </summary>
        /// <param name="buffer">Message bytes.</param>
        /// <returns>Parsed message.</returns>
        public static Smb1LogoffAndX ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 LOGOFF_ANDX message.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.LogoffAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_LOGOFF_ANDX command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 LOGOFF_ANDX message must use WordCount=2.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 LOGOFF_ANDX message must use ByteCount=0.");
            }

            return new Smb1LogoffAndX
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.LogoffAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
