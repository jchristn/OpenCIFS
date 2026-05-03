namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_NT_TRANSACT</c> response frame per MS-CIFS section 2.2.4.62.2.
    /// </summary>
    /// <remarks>
    /// The bounded codec carries the WordCount=18+SetupCount response shape with 32-bit
    /// TotalParameterCount/TotalDataCount/ParameterCount/ParameterOffset/ParameterDisplacement/
    /// DataCount/DataOffset/DataDisplacement, the variable-count Setup-word block, and the same
    /// 4-byte-aligned (Pad1 + Parameters + Pad2 + Data) ByteCount-prefixed payload as the primary
    /// request.
    /// </remarks>
    public sealed class Smb1NtTransactResponse
    {
        private const int FixedWordCountBaseline = 18;
        private const int FixedBaselineParameterWords = FixedWordCountBaseline * sizeof(ushort);

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
        public uint TotalParameterCount { get; set; }

        /// <summary>
        /// Total bytes of transaction data across all primary plus secondary responses.
        /// </summary>
        public uint TotalDataCount { get; set; }

        /// <summary>
        /// Byte offset within the total parameter block at which this response fragment begins.
        /// </summary>
        public uint ParameterDisplacement { get; set; }

        /// <summary>
        /// Byte offset within the total data block at which this response fragment begins.
        /// </summary>
        public uint DataDisplacement { get; set; }

        /// <summary>
        /// Setup words specific to the NT_TRANSACT sub-command response.
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
        /// Serialize the NT_TRANSACT response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.NtTransact)
            {
                throw new ProtocolValidationException("The SMB1 NT_TRANSACT response header command must be SMB_COM_NT_TRANSACT.", nameof(Header));
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
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 NT_TRANSACT response payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte((byte)(FixedWordCountBaseline + setupCount));
            writer.WriteByte(0);
            writer.WriteUInt16(0);
            writer.WriteUInt32(TotalParameterCount);
            writer.WriteUInt32(TotalDataCount);
            writer.WriteUInt32((uint)parameterCount);
            writer.WriteUInt32((uint)(parameterCount == 0 ? 0 : parameterOffset));
            writer.WriteUInt32(ParameterDisplacement);
            writer.WriteUInt32((uint)dataCount);
            writer.WriteUInt32((uint)(dataCount == 0 ? 0 : dataOffset));
            writer.WriteUInt32(DataDisplacement);
            writer.WriteByte(setupCount);

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
        /// Parse an SMB1 NT_TRANSACT response from its wire bytes.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1NtTransactResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumBaselineLength = ProtocolConstants.Smb1HeaderLength + 1 + FixedBaselineParameterWords + sizeof(ushort);

            if (buffer.Length < minimumBaselineLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 NT_TRANSACT response.");
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
                throw new ProtocolEncodingException("The SMB1 NT_TRANSACT response must use WordCount of at least 18.");
            }

            byte declaredSetupCount = (byte)(wordCount - FixedWordCountBaseline);
            reader.ReadByte();
            reader.ReadUInt16();
            uint totalParameterCount = reader.ReadUInt32();
            uint totalDataCount = reader.ReadUInt32();
            uint parameterCount = reader.ReadUInt32();
            uint parameterOffset = reader.ReadUInt32();
            uint parameterDisplacement = reader.ReadUInt32();
            uint dataCount = reader.ReadUInt32();
            uint dataOffset = reader.ReadUInt32();
            uint dataDisplacement = reader.ReadUInt32();
            byte setupCount = reader.ReadByte();

            if (setupCount != declaredSetupCount)
            {
                throw new ProtocolEncodingException("The SMB1 NT_TRANSACT response SetupCount does not match the WordCount-implied setup-word count.");
            }

            ushort[] setupWords = new ushort[setupCount];

            for (int index = 0; index < setupCount; index++)
            {
                setupWords[index] = reader.ReadUInt16();
            }

            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 NT_TRANSACT response ByteCount does not match the remaining payload length.");
            }

            ReadOnlySpan<byte> bufferSpan = buffer.Span;
            byte[] parameters = new byte[parameterCount];
            byte[] data = new byte[dataCount];

            if (parameterCount > 0)
            {
                if (parameterOffset > Int32.MaxValue || parameterOffset + parameterCount > (uint)buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 NT_TRANSACT response ParameterOffset/ParameterCount is invalid.");
                }

                bufferSpan.Slice((int)parameterOffset, (int)parameterCount).CopyTo(parameters);
            }

            if (dataCount > 0)
            {
                if (dataOffset > Int32.MaxValue || dataOffset + dataCount > (uint)buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 NT_TRANSACT response DataOffset/DataCount is invalid.");
                }

                bufferSpan.Slice((int)dataOffset, (int)dataCount).CopyTo(data);
            }

            return new Smb1NtTransactResponse
            {
                Header = header,
                TotalParameterCount = totalParameterCount,
                TotalDataCount = totalDataCount,
                ParameterDisplacement = parameterDisplacement,
                DataDisplacement = dataDisplacement,
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
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
