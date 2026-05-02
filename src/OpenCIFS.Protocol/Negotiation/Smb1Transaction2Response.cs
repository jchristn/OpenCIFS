namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_TRANSACTION2</c> response frame per MS-CIFS section 2.2.4.46.2.
    /// </summary>
    /// <remarks>
    /// The bounded codec carries the standard WordCount=10 response shape with zero Setup words
    /// (the typical Trans2 sub-command response shape; <c>FIND_FIRST2</c> and similar return their
    /// search-handle data in the parameter block, not in setup words). Parameter and data bytes
    /// are written at offsets aligned to 4-byte boundaries from the SMB header start so the
    /// canonical Pad1 and Pad2 alignment bytes always land on stable offsets. Multi-fragment
    /// Trans2 responses (with non-zero ParameterDisplacement / DataDisplacement) round-trip but
    /// do not yet drive a managed reassembler.
    /// </remarks>
    public sealed class Smb1Transaction2Response
    {
        private const byte WordCountValue = 0x0A;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte SetupCountValue = 0x00;

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
        /// Total bytes of transaction parameters across all primary plus secondary responses.
        /// </summary>
        public ushort TotalParameterCount { get; set; }

        /// <summary>
        /// Total bytes of transaction data across all primary plus secondary responses.
        /// </summary>
        public ushort TotalDataCount { get; set; }

        /// <summary>
        /// Byte offset within the total parameter block at which this response fragment begins.
        /// </summary>
        public ushort ParameterDisplacement { get; set; }

        /// <summary>
        /// Byte offset within the total data block at which this response fragment begins.
        /// </summary>
        public ushort DataDisplacement { get; set; }

        /// <summary>
        /// Transaction parameter bytes carried by this response fragment.
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
        /// Transaction data bytes carried by this response fragment.
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
        /// Serialize the TRANSACTION2 response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Transaction2)
            {
                throw new ProtocolValidationException("The SMB1 TRANSACTION2 response header command must be SMB_COM_TRANSACTION2.", nameof(Header));
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
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 TRANSACTION2 response payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(TotalParameterCount);
            writer.WriteUInt16(TotalDataCount);
            writer.WriteUInt16(0);
            writer.WriteUInt16((ushort)parameterCount);
            writer.WriteUInt16((ushort)(parameterCount == 0 ? 0 : parameterOffset));
            writer.WriteUInt16(ParameterDisplacement);
            writer.WriteUInt16((ushort)dataCount);
            writer.WriteUInt16((ushort)(dataCount == 0 ? 0 : dataOffset));
            writer.WriteUInt16(DataDisplacement);
            writer.WriteByte(SetupCountValue);
            writer.WriteByte(0);
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
        /// Parse an SMB1 TRANSACTION2 response from its wire bytes.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1Transaction2Response ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TRANSACTION2 response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.Transaction2)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_TRANSACTION2 command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TRANSACTION2 response codec requires WordCount=10.");
            }

            ushort totalParameterCount = reader.ReadUInt16();
            ushort totalDataCount = reader.ReadUInt16();
            reader.ReadUInt16();
            ushort parameterCount = reader.ReadUInt16();
            ushort parameterOffset = reader.ReadUInt16();
            ushort parameterDisplacement = reader.ReadUInt16();
            ushort dataCount = reader.ReadUInt16();
            ushort dataOffset = reader.ReadUInt16();
            ushort dataDisplacement = reader.ReadUInt16();
            byte setupCount = reader.ReadByte();
            reader.ReadByte();

            if (setupCount != SetupCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TRANSACTION2 response codec requires zero Setup words.");
            }

            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 response ByteCount does not match the remaining payload length.");
            }

            int payloadAbsoluteStart = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

            if (parameterOffset != 0 && parameterOffset < payloadAbsoluteStart)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 response ParameterOffset points before the data section.");
            }

            if (dataOffset != 0 && dataOffset < payloadAbsoluteStart)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 response DataOffset points before the data section.");
            }

            byte[] parameters = new byte[parameterCount];
            byte[] data = new byte[dataCount];
            ReadOnlySpan<byte> bufferSpan = buffer.Span;

            if (parameterCount > 0)
            {
                int absoluteEnd = parameterOffset + parameterCount;

                if (absoluteEnd > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION2 response ParameterCount exceeds the buffer length.");
                }

                bufferSpan.Slice(parameterOffset, parameterCount).CopyTo(parameters);
            }

            if (dataCount > 0)
            {
                int absoluteEnd = dataOffset + dataCount;

                if (absoluteEnd > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION2 response DataCount exceeds the buffer length.");
                }

                bufferSpan.Slice(dataOffset, dataCount).CopyTo(data);
            }

            return new Smb1Transaction2Response
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
            Command = Smb1Command.Transaction2,
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
