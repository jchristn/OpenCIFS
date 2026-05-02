namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_TRANSACTION2</c> primary request frame per MS-CIFS section 2.2.4.46.1.
    /// </summary>
    /// <remarks>
    /// The bounded codec carries the WordCount=15 primary-request shape with exactly one Setup
    /// word identifying the Trans2 <see cref="SubCommand" />. Parameter and data bytes are written
    /// at offsets aligned to 4-byte boundaries from the SMB header start so the canonical Pad1
    /// and Pad2 alignment bytes always land on stable offsets. The single trailing transaction
    /// name byte is always a null terminator since Trans2 does not carry a transaction name.
    /// Multi-fragment Trans2 traffic (TRANSACTION2_SECONDARY) remains backlog and is not handled
    /// by this frame.
    /// </remarks>
    public sealed class Smb1Transaction2Request
    {
        private const byte WordCountValue = 0x0F;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte SetupCountValue = 0x01;

        /// <summary>
        /// Trans2 transaction-flags bit indicating that the originating tree should be
        /// disconnected after the transaction completes.
        /// </summary>
        public const ushort FlagDisconnectTid = 0x0001;

        /// <summary>
        /// Trans2 transaction-flags bit indicating that the response is one-way.
        /// </summary>
        public const ushort FlagOneWay = 0x0002;

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
        /// Trans2 sub-command identifying the operation carried in this request.
        /// </summary>
        public Smb1Transaction2SubCommand SubCommand { get; set; }

        /// <summary>
        /// Total bytes of transaction parameters across all primary plus secondary requests.
        /// </summary>
        public ushort TotalParameterCount { get; set; }

        /// <summary>
        /// Total bytes of transaction data across all primary plus secondary requests.
        /// </summary>
        public ushort TotalDataCount { get; set; }

        /// <summary>
        /// Maximum bytes of transaction parameters the server may return in the response.
        /// </summary>
        public ushort MaxParameterCount { get; set; }

        /// <summary>
        /// Maximum bytes of transaction data the server may return in the response.
        /// </summary>
        public ushort MaxDataCount { get; set; }

        /// <summary>
        /// Maximum number of setup words the server may return in the response.
        /// </summary>
        public byte MaxSetupCount { get; set; }

        /// <summary>
        /// Trans2 transaction flags (e.g. <see cref="FlagDisconnectTid" />, <see cref="FlagOneWay" />).
        /// </summary>
        public ushort Flags { get; set; }

        /// <summary>
        /// Server-side transaction timeout in milliseconds; advisory.
        /// </summary>
        public uint Timeout { get; set; }

        /// <summary>
        /// Transaction parameter bytes carried by this primary request fragment.
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
        /// Transaction data bytes carried by this primary request fragment.
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
        /// Serialize the TRANSACTION2 primary request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Transaction2)
            {
                throw new ProtocolValidationException("The SMB1 TRANSACTION2 request header command must be SMB_COM_TRANSACTION2.", nameof(Header));
            }

            int parameterCount = Parameters.Length;
            int dataCount = Data.Length;
            int afterByteCount = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);
            int afterName = afterByteCount + 1;
            int pad1Length = (4 - (afterName & 3)) & 3;
            int parameterOffset = afterName + pad1Length;
            int afterParameters = parameterOffset + parameterCount;
            int pad2Length = (4 - (afterParameters & 3)) & 3;
            int dataOffset = afterParameters + pad2Length;
            int byteCount = 1 + pad1Length + parameterCount + pad2Length + dataCount;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 TRANSACTION2 primary-request payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(TotalParameterCount);
            writer.WriteUInt16(TotalDataCount);
            writer.WriteUInt16(MaxParameterCount);
            writer.WriteUInt16(MaxDataCount);
            writer.WriteByte(MaxSetupCount);
            writer.WriteByte(0);
            writer.WriteUInt16(Flags);
            writer.WriteUInt32(Timeout);
            writer.WriteUInt16(0);
            writer.WriteUInt16((ushort)parameterCount);
            writer.WriteUInt16((ushort)parameterOffset);
            writer.WriteUInt16((ushort)dataCount);
            writer.WriteUInt16((ushort)dataOffset);
            writer.WriteByte(SetupCountValue);
            writer.WriteByte(0);
            writer.WriteUInt16((ushort)SubCommand);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteByte(0);

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
        /// Parse an SMB1 TRANSACTION2 primary request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1Transaction2Request ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TRANSACTION2 request.");
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
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 primary request must use WordCount=15.");
            }

            ushort totalParameterCount = reader.ReadUInt16();
            ushort totalDataCount = reader.ReadUInt16();
            ushort maxParameterCount = reader.ReadUInt16();
            ushort maxDataCount = reader.ReadUInt16();
            byte maxSetupCount = reader.ReadByte();
            reader.ReadByte();
            ushort flags = reader.ReadUInt16();
            uint timeout = reader.ReadUInt32();
            reader.ReadUInt16();
            ushort parameterCount = reader.ReadUInt16();
            ushort parameterOffset = reader.ReadUInt16();
            ushort dataCount = reader.ReadUInt16();
            ushort dataOffset = reader.ReadUInt16();
            byte setupCount = reader.ReadByte();
            reader.ReadByte();

            if (setupCount != SetupCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TRANSACTION2 request codec requires exactly one Setup word.");
            }

            ushort subCommand = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 request ByteCount does not match the remaining payload length.");
            }

            int byteCountAbsoluteOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength;
            int payloadAbsoluteStart = byteCountAbsoluteOffset + sizeof(ushort);

            if (parameterOffset != 0 && parameterOffset < payloadAbsoluteStart)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 request ParameterOffset points before the data section.");
            }

            if (dataOffset != 0 && dataOffset < payloadAbsoluteStart)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION2 request DataOffset points before the data section.");
            }

            byte[] parameters = new byte[parameterCount];
            byte[] data = new byte[dataCount];

            ReadOnlySpan<byte> bufferSpan = buffer.Span;

            if (parameterCount > 0)
            {
                int absoluteEnd = parameterOffset + parameterCount;

                if (absoluteEnd > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION2 request ParameterCount exceeds the buffer length.");
                }

                bufferSpan.Slice(parameterOffset, parameterCount).CopyTo(parameters);
            }

            if (dataCount > 0)
            {
                int absoluteEnd = dataOffset + dataCount;

                if (absoluteEnd > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION2 request DataCount exceeds the buffer length.");
                }

                bufferSpan.Slice(dataOffset, dataCount).CopyTo(data);
            }

            return new Smb1Transaction2Request
            {
                Header = header,
                SubCommand = (Smb1Transaction2SubCommand)subCommand,
                TotalParameterCount = totalParameterCount,
                TotalDataCount = totalDataCount,
                MaxParameterCount = maxParameterCount,
                MaxDataCount = maxDataCount,
                MaxSetupCount = maxSetupCount,
                Flags = flags,
                Timeout = timeout,
                Parameters = parameters,
                Data = data
            };
        }

        private byte[] _Parameters = Array.Empty<byte>();
        private byte[] _Data = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.Transaction2,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
