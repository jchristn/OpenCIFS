namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_READ_ANDX</c> response carrying the read data block.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.42.2. The response carries WordCount=12 with a DataOffset that points
    /// at the read payload relative to the SMB header start; the bounded codec emits a 1-byte
    /// alignment pad between the ByteCount field and the data block so DataOffset always lands on
    /// an even byte. <see cref="DataLengthHigh" /> carries the upper 16 bits of the read length for
    /// SMB 1.0 large-read extensions.
    /// </remarks>
    public sealed class Smb1ReadAndXResponse
    {
        private const byte WordCountValue = 0x0C;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;
        private static readonly int FixedDataOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort) + 1;

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
        /// Bytes still available on the underlying handle. Advisory.
        /// </summary>
        public ushort Available { get; set; }

        /// <summary>
        /// Data compaction mode. Always zero for the bounded codec.
        /// </summary>
        public ushort DataCompactionMode { get; set; }

        /// <summary>
        /// Upper 16 bits of the data-length field for large-read extensions.
        /// </summary>
        public ushort DataLengthHigh { get; set; }

        /// <summary>
        /// Read payload returned to the caller. The lower 16 bits of <see cref="DataLengthHigh" />
        /// plus the on-wire DataLength must equal <see cref="Data" /> length.
        /// </summary>
        public byte[] Data
        {
            get
            {
                return _Data;
            }
            set
            {
                _Data = value ?? throw new ArgumentNullException(nameof(Data), "Data cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the READ_ANDX response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.ReadAndX)
            {
                throw new ProtocolValidationException("The SMB1 READ_ANDX response header command must be SMB_COM_READ_ANDX.", nameof(Header));
            }

            int dataLength = Data.Length;

            if (dataLength > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 READ_ANDX response payload exceeds the 16-bit DataLength field for the bounded codec.");
            }

            int padLength = 1;
            int byteCount = padLength + dataLength;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 READ_ANDX response payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(Available);
            writer.WriteUInt16(DataCompactionMode);
            writer.WriteUInt16(0);
            writer.WriteUInt16((ushort)dataLength);
            writer.WriteUInt16((ushort)FixedDataOffset);
            writer.WriteUInt16(DataLengthHigh);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteByte(0);
            writer.WriteBytes(Data);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 READ_ANDX response from its wire bytes.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1ReadAndXResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 READ_ANDX response.");
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
                throw new ProtocolEncodingException("The bounded SMB1 READ_ANDX response codec requires WordCount=12.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort available = reader.ReadUInt16();
            ushort dataCompactionMode = reader.ReadUInt16();
            reader.ReadUInt16();
            ushort dataLength = reader.ReadUInt16();
            ushort dataOffset = reader.ReadUInt16();
            ushort dataLengthHigh = reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 READ_ANDX response ByteCount does not match the remaining payload length.");
            }

            int dataAbsoluteOffset = dataOffset;
            int currentAbsoluteOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

            if (dataAbsoluteOffset < currentAbsoluteOffset)
            {
                throw new ProtocolEncodingException("The SMB1 READ_ANDX response DataOffset points before the data section.");
            }

            int padLength = dataAbsoluteOffset - currentAbsoluteOffset;

            if (padLength + dataLength > byteCount)
            {
                throw new ProtocolEncodingException("The SMB1 READ_ANDX response DataOffset and DataLength exceed the ByteCount payload.");
            }

            reader.Skip(padLength);
            byte[] data = reader.ReadBytes(dataLength);
            int trailingPadding = byteCount - padLength - dataLength;

            if (trailingPadding > 0)
            {
                reader.Skip(trailingPadding);
            }

            return new Smb1ReadAndXResponse
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                Available = available,
                DataCompactionMode = dataCompactionMode,
                DataLengthHigh = dataLengthHigh,
                Data = data
            };
        }

        private byte[] _Data = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.ReadAndX,
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
