namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_NT_TRANSACT</c> primary request frame per MS-CIFS section 2.2.4.62.1.
    /// </summary>
    /// <remarks>
    /// The bounded codec carries the WordCount=19+SetupCount primary-request shape with 32-bit
    /// parameter and data length fields plus a 16-bit Function code identifying the NT_TRANSACT
    /// sub-command (e.g. NT_TRANSACT_CREATE = 1, NT_TRANSACT_IOCTL = 2, NT_TRANSACT_NOTIFY_CHANGE
    /// = 4, NT_TRANSACT_QUERY_SECURITY_DESC = 6, NT_TRANSACT_SET_SECURITY_DESC = 3). NT_TRANSACT
    /// does not carry a transaction Name.
    /// </remarks>
    public sealed class Smb1NtTransactRequest
    {
        private const int FixedWordCountBaseline = 19;
        private const int FixedBaselineParameterWords = FixedWordCountBaseline * sizeof(ushort);

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
        /// Maximum number of setup words the server may return in the response.
        /// </summary>
        public byte MaxSetupCount { get; set; }

        /// <summary>
        /// Total bytes of transaction parameters across all primary plus secondary requests.
        /// </summary>
        public uint TotalParameterCount { get; set; }

        /// <summary>
        /// Total bytes of transaction data across all primary plus secondary requests.
        /// </summary>
        public uint TotalDataCount { get; set; }

        /// <summary>
        /// Maximum bytes of transaction parameters the server may return in the response.
        /// </summary>
        public uint MaxParameterCount { get; set; }

        /// <summary>
        /// Maximum bytes of transaction data the server may return in the response.
        /// </summary>
        public uint MaxDataCount { get; set; }

        /// <summary>
        /// NT_TRANSACT sub-command code.
        /// </summary>
        public ushort Function { get; set; }

        /// <summary>
        /// Setup words specific to the NT_TRANSACT sub-command.
        /// </summary>
        public ushort[] Setup
        {
            get
            {
                return _Setup;
            }
            set
            {
                _Setup = value ?? throw new ArgumentNullException(nameof(Setup), "Setup cannot be null.");
            }
        }

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
        /// Serialize the NT_TRANSACT primary request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.NtTransact)
            {
                throw new ProtocolValidationException("The SMB1 NT_TRANSACT request header command must be SMB_COM_NT_TRANSACT.", nameof(Header));
            }

            if (Setup.Length > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Setup), "SetupCount cannot exceed 255.");
            }

            byte setupCount = (byte)Setup.Length;
            int parameterWordsLength = FixedBaselineParameterWords + (setupCount * sizeof(ushort));
            int parameterCount = Parameters.Length;
            int dataCount = Data.Length;

            int afterByteCount = ProtocolConstants.Smb1HeaderLength + 1 + parameterWordsLength + sizeof(ushort);
            int pad1Length = (4 - (afterByteCount & 3)) & 3;
            int parameterOffset = afterByteCount + pad1Length;
            int afterParameters = parameterOffset + parameterCount;
            int pad2Length = (4 - (afterParameters & 3)) & 3;
            int dataOffset = afterParameters + pad2Length;
            int byteCount = pad1Length + parameterCount + pad2Length + dataCount;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 NT_TRANSACT primary-request payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte((byte)(FixedWordCountBaseline + setupCount));
            writer.WriteByte(MaxSetupCount);
            writer.WriteUInt16(0);
            writer.WriteUInt32(TotalParameterCount);
            writer.WriteUInt32(TotalDataCount);
            writer.WriteUInt32(MaxParameterCount);
            writer.WriteUInt32(MaxDataCount);
            writer.WriteUInt32((uint)parameterCount);
            writer.WriteUInt32((uint)(parameterCount == 0 ? 0 : parameterOffset));
            writer.WriteUInt32((uint)dataCount);
            writer.WriteUInt32((uint)(dataCount == 0 ? 0 : dataOffset));
            writer.WriteByte(setupCount);
            writer.WriteUInt16(Function);

            for (int index = 0; index < setupCount; index++)
            {
                writer.WriteUInt16(Setup[index]);
            }

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
        /// Parse an SMB1 NT_TRANSACT primary request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1NtTransactRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumBaselineLength = ProtocolConstants.Smb1HeaderLength + 1 + FixedBaselineParameterWords + sizeof(ushort);

            if (buffer.Length < minimumBaselineLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 NT_TRANSACT request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.NtTransact)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_NT_TRANSACT command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount < FixedWordCountBaseline)
            {
                throw new ProtocolEncodingException("The SMB1 NT_TRANSACT primary request must use WordCount of at least 19.");
            }

            byte declaredSetupCountFromWordCount = (byte)(wordCount - FixedWordCountBaseline);
            byte maxSetupCount = reader.ReadByte();
            reader.ReadUInt16();
            uint totalParameterCount = reader.ReadUInt32();
            uint totalDataCount = reader.ReadUInt32();
            uint maxParameterCount = reader.ReadUInt32();
            uint maxDataCount = reader.ReadUInt32();
            uint parameterCount = reader.ReadUInt32();
            uint parameterOffset = reader.ReadUInt32();
            uint dataCount = reader.ReadUInt32();
            uint dataOffset = reader.ReadUInt32();
            byte setupCount = reader.ReadByte();
            ushort function = reader.ReadUInt16();

            if (setupCount != declaredSetupCountFromWordCount)
            {
                throw new ProtocolEncodingException("The SMB1 NT_TRANSACT request SetupCount does not match the WordCount-implied setup-word count.");
            }

            ushort[] setupWords = new ushort[setupCount];

            for (int index = 0; index < setupCount; index++)
            {
                setupWords[index] = reader.ReadUInt16();
            }

            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 NT_TRANSACT request ByteCount does not match the remaining payload length.");
            }

            ReadOnlySpan<byte> bufferSpan = buffer.Span;
            byte[] parameters = new byte[parameterCount];
            byte[] data = new byte[dataCount];

            if (parameterCount > 0)
            {
                if (parameterOffset > Int32.MaxValue || parameterOffset + parameterCount > (uint)buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 NT_TRANSACT request ParameterOffset/ParameterCount is invalid.");
                }

                bufferSpan.Slice((int)parameterOffset, (int)parameterCount).CopyTo(parameters);
            }

            if (dataCount > 0)
            {
                if (dataOffset > Int32.MaxValue || dataOffset + dataCount > (uint)buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 NT_TRANSACT request DataOffset/DataCount is invalid.");
                }

                bufferSpan.Slice((int)dataOffset, (int)dataCount).CopyTo(data);
            }

            return new Smb1NtTransactRequest
            {
                Header = header,
                MaxSetupCount = maxSetupCount,
                TotalParameterCount = totalParameterCount,
                TotalDataCount = totalDataCount,
                MaxParameterCount = maxParameterCount,
                MaxDataCount = maxDataCount,
                Function = function,
                Setup = setupWords,
                Parameters = parameters,
                Data = data
            };
        }

        private byte[] _Parameters = Array.Empty<byte>();
        private byte[] _Data = Array.Empty<byte>();
        private ushort[] _Setup = Array.Empty<ushort>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.NtTransact,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
