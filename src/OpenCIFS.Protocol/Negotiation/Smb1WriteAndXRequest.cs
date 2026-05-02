namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_WRITE_ANDX</c> request used to write a buffer to an open file or pipe.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.43.1. The bounded codec only supports the WordCount=14 shape that
    /// carries a 64-bit file offset (Offset + OffsetHigh). The bounded codec emits a 1-byte
    /// alignment pad between the ByteCount field and the data block so DataOffset always lands on
    /// an even byte. <see cref="DataLengthHigh" /> carries the upper 16 bits of the write length
    /// for SMB 1.0 large-write extensions.
    /// </remarks>
    public sealed class Smb1WriteAndXRequest
    {
        private const byte WordCountValue = 0x0E;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;
        private static readonly int FixedDataOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort) + 1;

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
        /// 64-bit file offset where the data should be written.
        /// </summary>
        public ulong FileOffset { get; set; }

        /// <summary>
        /// Reserved or pipe-write timeout. Always zero for file writes.
        /// </summary>
        public uint TimeoutOrReserved { get; set; }

        /// <summary>
        /// Write-mode bit field (e.g. write-through, message-start, raw).
        /// </summary>
        public ushort WriteMode { get; set; }

        /// <summary>
        /// Bytes still expected from a follow-up write. Advisory.
        /// </summary>
        public ushort Remaining { get; set; }

        /// <summary>
        /// Upper 16 bits of the data-length field for large-write extensions.
        /// </summary>
        public ushort DataLengthHigh { get; set; }

        /// <summary>
        /// Write payload sent to the server. The lower 16 bits of the field plus
        /// <see cref="DataLengthHigh" /> must equal <see cref="Data" /> length.
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
        /// Serialize the WRITE_ANDX request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.WriteAndX)
            {
                throw new ProtocolValidationException("The SMB1 WRITE_ANDX request header command must be SMB_COM_WRITE_ANDX.", nameof(Header));
            }

            int dataLength = Data.Length;

            if (dataLength > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 WRITE_ANDX request payload exceeds the 16-bit DataLength field for the bounded codec.");
            }

            int padLength = 1;
            int byteCount = padLength + dataLength;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 WRITE_ANDX request payload exceeds the 16-bit ByteCount field.");
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
            writer.WriteUInt32(TimeoutOrReserved);
            writer.WriteUInt16(WriteMode);
            writer.WriteUInt16(Remaining);
            writer.WriteUInt16(DataLengthHigh);
            writer.WriteUInt16((ushort)dataLength);
            writer.WriteUInt16((ushort)FixedDataOffset);
            writer.WriteUInt32(offsetHigh);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteByte(0);
            writer.WriteBytes(Data);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 WRITE_ANDX request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1WriteAndXRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 WRITE_ANDX request.");
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
                throw new ProtocolEncodingException("The bounded SMB1 WRITE_ANDX request codec requires WordCount=14.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort fileId = reader.ReadUInt16();
            uint offsetLow = reader.ReadUInt32();
            uint timeoutOrReserved = reader.ReadUInt32();
            ushort writeMode = reader.ReadUInt16();
            ushort remaining = reader.ReadUInt16();
            ushort dataLengthHigh = reader.ReadUInt16();
            ushort dataLength = reader.ReadUInt16();
            ushort dataOffset = reader.ReadUInt16();
            uint offsetHigh = reader.ReadUInt32();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 WRITE_ANDX request ByteCount does not match the remaining payload length.");
            }

            int dataAbsoluteOffset = dataOffset;
            int currentAbsoluteOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

            if (dataAbsoluteOffset < currentAbsoluteOffset)
            {
                throw new ProtocolEncodingException("The SMB1 WRITE_ANDX request DataOffset points before the data section.");
            }

            int padLength = dataAbsoluteOffset - currentAbsoluteOffset;

            if (padLength + dataLength > byteCount)
            {
                throw new ProtocolEncodingException("The SMB1 WRITE_ANDX request DataOffset and DataLength exceed the ByteCount payload.");
            }

            reader.Skip(padLength);
            byte[] data = reader.ReadBytes(dataLength);
            int trailingPadding = byteCount - padLength - dataLength;

            if (trailingPadding > 0)
            {
                reader.Skip(trailingPadding);
            }

            ulong fileOffset = ((ulong)offsetHigh << 32) | offsetLow;

            return new Smb1WriteAndXRequest
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                FileId = fileId,
                FileOffset = fileOffset,
                TimeoutOrReserved = timeoutOrReserved,
                WriteMode = writeMode,
                Remaining = remaining,
                DataLengthHigh = dataLengthHigh,
                Data = data
            };
        }

        private byte[] _Data = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.WriteAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
