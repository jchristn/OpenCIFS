namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_READ_ANDX</c> request used to read a range of bytes from an open file.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.42.1. The bounded codec only supports the WordCount=12 shape that
    /// carries a 64-bit file offset (Offset + OffsetHigh) so callers can address files larger than
    /// 4 GB. ByteCount is always zero on the request side.
    /// </remarks>
    public sealed class Smb1ReadAndXRequest
    {
        private const byte WordCountValue = 0x0C;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;

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
        /// SMB1 file identifier returned by the prior open.
        /// </summary>
        public ushort FileId { get; set; }

        /// <summary>
        /// 64-bit file offset of the first byte to read.
        /// </summary>
        public ulong FileOffset { get; set; }

        /// <summary>
        /// Maximum number of bytes the server should return.
        /// </summary>
        public ushort MaxCountOfBytesToReturn { get; set; }

        /// <summary>
        /// Minimum number of bytes the server should return before completing the request.
        /// </summary>
        public ushort MinCountOfBytesToReturn { get; set; }

        /// <summary>
        /// Upper 32 bits of the maximum-count field used by SMB 1.0 large-read extensions, or
        /// <c>0xFFFFFFFF</c> when used as a Timeout placeholder for non-pipe reads.
        /// </summary>
        public uint TimeoutOrMaxCountHigh { get; set; }

        /// <summary>
        /// Bytes still expected from a follow-up read on the same file. Advisory.
        /// </summary>
        public ushort Remaining { get; set; }

        /// <summary>
        /// Serialize the READ_ANDX request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.ReadAndX)
            {
                throw new ProtocolValidationException("The SMB1 READ_ANDX request header command must be SMB_COM_READ_ANDX.", nameof(Header));
            }

            uint offsetLow = unchecked((uint)(FileOffset & 0xFFFFFFFFU));
            uint offsetHigh = unchecked((uint)((FileOffset >> 32) & 0xFFFFFFFFU));

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(FileId);
            writer.WriteUInt32(offsetLow);
            writer.WriteUInt16(MaxCountOfBytesToReturn);
            writer.WriteUInt16(MinCountOfBytesToReturn);
            writer.WriteUInt32(TimeoutOrMaxCountHigh);
            writer.WriteUInt16(Remaining);
            writer.WriteUInt32(offsetHigh);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 READ_ANDX request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1ReadAndXRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 READ_ANDX request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.ReadAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_READ_ANDX command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 READ_ANDX request codec requires WordCount=12.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort fileId = reader.ReadUInt16();
            uint offsetLow = reader.ReadUInt32();
            ushort maxCount = reader.ReadUInt16();
            ushort minCount = reader.ReadUInt16();
            uint timeoutOrMaxCountHigh = reader.ReadUInt32();
            ushort remaining = reader.ReadUInt16();
            uint offsetHigh = reader.ReadUInt32();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 READ_ANDX request must use ByteCount=0.");
            }

            ulong fileOffset = ((ulong)offsetHigh << 32) | offsetLow;

            return new Smb1ReadAndXRequest
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                FileId = fileId,
                FileOffset = fileOffset,
                MaxCountOfBytesToReturn = maxCount,
                MinCountOfBytesToReturn = minCount,
                TimeoutOrMaxCountHigh = timeoutOrMaxCountHigh,
                Remaining = remaining
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.ReadAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
