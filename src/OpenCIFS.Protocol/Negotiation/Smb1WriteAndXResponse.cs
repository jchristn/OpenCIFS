namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_WRITE_ANDX</c> response acknowledging the write.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.43.2. The response carries WordCount=6 (Count, Available, CountHigh,
    /// Reserved) and ByteCount=0. <see cref="CountHigh" /> carries the upper 16 bits of the
    /// acknowledged byte count for SMB 1.0 large-write extensions.
    /// </remarks>
    public sealed class Smb1WriteAndXResponse
    {
        private const byte WordCountValue = 0x06;
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
        /// Lower 16 bits of the byte count successfully written.
        /// </summary>
        public ushort Count { get; set; }

        /// <summary>
        /// Bytes still available on the underlying handle. Advisory.
        /// </summary>
        public ushort Available { get; set; }

        /// <summary>
        /// Upper 16 bits of the byte count for large-write extensions.
        /// </summary>
        public ushort CountHigh { get; set; }

        /// <summary>
        /// Serialize the WRITE_ANDX response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.WriteAndX)
            {
                throw new ProtocolValidationException("The SMB1 WRITE_ANDX response header command must be SMB_COM_WRITE_ANDX.", nameof(Header));
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(Count);
            writer.WriteUInt16(Available);
            writer.WriteUInt16(CountHigh);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 WRITE_ANDX response from its wire bytes.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1WriteAndXResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 WRITE_ANDX response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.WriteAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_WRITE_ANDX command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 WRITE_ANDX response must use WordCount=6.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort count = reader.ReadUInt16();
            ushort available = reader.ReadUInt16();
            ushort countHigh = reader.ReadUInt16();
            reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 WRITE_ANDX response must use ByteCount=0.");
            }

            return new Smb1WriteAndXResponse
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                Count = count,
                Available = available,
                CountHigh = countHigh
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.WriteAndX,
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
