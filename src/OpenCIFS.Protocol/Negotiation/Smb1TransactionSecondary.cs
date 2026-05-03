namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_TRANSACTION_SECONDARY</c> fragment per MS-CIFS section 2.2.4.34.1.
    /// </summary>
    /// <remarks>
    /// Carries a continuation fragment of an in-progress <see cref="Smb1Command.Transaction" />
    /// request when the primary fragment indicated more parameter or data bytes were coming. The
    /// codec carries the WordCount=8 fixed-shape fields and the same 4-byte-aligned (Pad1 +
    /// Parameters + Pad2 + Data) ByteCount-prefixed payload as the primary request. Setup words
    /// are not present on secondary fragments.
    /// </remarks>
    public sealed class Smb1TransactionSecondary
    {
        private const byte WordCountValue = 0x08;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);

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
        /// Total bytes of transaction parameters across all primary plus secondary requests.
        /// </summary>
        public ushort TotalParameterCount { get; set; }

        /// <summary>
        /// Total bytes of transaction data across all primary plus secondary requests.
        /// </summary>
        public ushort TotalDataCount { get; set; }

        /// <summary>
        /// Byte offset within the total parameter block at which this secondary fragment begins.
        /// </summary>
        public ushort ParameterDisplacement { get; set; }

        /// <summary>
        /// Byte offset within the total data block at which this secondary fragment begins.
        /// </summary>
        public ushort DataDisplacement { get; set; }

        /// <summary>
        /// Transaction parameter bytes carried by this secondary fragment.
        /// </summary>
        public byte[] Parameters
        {
            get
            {
                return _Parameters;
            }
            set
            {
                _Parameters = value ?? throw new ArgumentNullException(nameof(Parameters), "Parameters cannot be null.");
            }
        }

        /// <summary>
        /// Transaction data bytes carried by this secondary fragment.
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
        /// Serialize the TRANSACTION_SECONDARY fragment to its SMB1 wire format.
        /// </summary>
        /// <returns>Fragment bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.TransactionSecondary)
            {
                throw new ProtocolValidationException("The SMB1 TRANSACTION_SECONDARY header command must be SMB_COM_TRANSACTION_SECONDARY.", nameof(Header));
            }

            int parameterCount = Parameters.Length;
            int dataCount = Data.Length;
            int afterByteCount = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);
            int pad1Length = (4 - (afterByteCount & 3)) & 3;
            int parameterOffset = afterByteCount + pad1Length;
            int afterParameters = parameterOffset + parameterCount;
            int pad2Length = (4 - (afterParameters & 3)) & 3;
            int dataOffset = afterParameters + pad2Length;
            int byteCount = pad1Length + parameterCount + pad2Length + dataCount;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 TRANSACTION_SECONDARY payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(TotalParameterCount);
            writer.WriteUInt16(TotalDataCount);
            writer.WriteUInt16((ushort)parameterCount);
            writer.WriteUInt16((ushort)(parameterCount == 0 ? 0 : parameterOffset));
            writer.WriteUInt16(ParameterDisplacement);
            writer.WriteUInt16((ushort)dataCount);
            writer.WriteUInt16((ushort)(dataCount == 0 ? 0 : dataOffset));
            writer.WriteUInt16(DataDisplacement);
            writer.WriteUInt16((ushort)byteCount);

            for (int index = 0; index < pad1Length; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(Parameters);

            for (int index = 0; index < pad2Length; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(Data);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 TRANSACTION_SECONDARY fragment from its wire bytes.
        /// </summary>
        /// <param name="buffer">Fragment bytes.</param>
        /// <returns>Parsed fragment.</returns>
        public static Smb1TransactionSecondary ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TRANSACTION_SECONDARY fragment.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.TransactionSecondary)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_TRANSACTION_SECONDARY command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION_SECONDARY fragment must use WordCount=8.");
            }

            ushort totalParameterCount = reader.ReadUInt16();
            ushort totalDataCount = reader.ReadUInt16();
            ushort parameterCount = reader.ReadUInt16();
            ushort parameterOffset = reader.ReadUInt16();
            ushort parameterDisplacement = reader.ReadUInt16();
            ushort dataCount = reader.ReadUInt16();
            ushort dataOffset = reader.ReadUInt16();
            ushort dataDisplacement = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION_SECONDARY ByteCount does not match the remaining payload length.");
            }

            int payloadAbsoluteStart = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);
            ReadOnlySpan<byte> bufferSpan = buffer.Span;
            byte[] parameters = new byte[parameterCount];
            byte[] data = new byte[dataCount];

            if (parameterCount > 0)
            {
                if (parameterOffset < payloadAbsoluteStart || parameterOffset + parameterCount > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION_SECONDARY ParameterOffset/ParameterCount is invalid.");
                }

                bufferSpan.Slice(parameterOffset, parameterCount).CopyTo(parameters);
            }

            if (dataCount > 0)
            {
                if (dataOffset < payloadAbsoluteStart || dataOffset + dataCount > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION_SECONDARY DataOffset/DataCount is invalid.");
                }

                bufferSpan.Slice(dataOffset, dataCount).CopyTo(data);
            }

            return new Smb1TransactionSecondary
            {
                Header = header,
                TotalParameterCount = totalParameterCount,
                TotalDataCount = totalDataCount,
                ParameterDisplacement = parameterDisplacement,
                DataDisplacement = dataDisplacement,
                Parameters = parameters,
                Data = data
            };
        }

        private byte[] _Parameters = Array.Empty<byte>();
        private byte[] _Data = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.TransactionSecondary,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
