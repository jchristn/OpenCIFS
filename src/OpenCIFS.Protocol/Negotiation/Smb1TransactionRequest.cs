namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_TRANSACTION</c> primary request frame per MS-CIFS section 2.2.4.33.1.
    /// </summary>
    /// <remarks>
    /// The bounded codec carries the WordCount=14+SetupCount primary-request shape with up to
    /// three Setup words. Trans1 traffic typically targets named pipes (<c>\PIPE\&lt;name&gt;</c>) or
    /// MailSlot endpoints, so a non-empty <see cref="Name" /> is the norm; the bounded codec
    /// supports both Unicode (<see cref="Smb1HeaderFlags2.Unicode" /> set) and ASCII names with the
    /// canonical Pad-before-Name alignment to a 2-byte boundary on Unicode headers.
    /// </remarks>
    public sealed class Smb1TransactionRequest
    {
        private const int FixedWordCountBaseline = 14;
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
        /// Trans1 transaction flags.
        /// </summary>
        public ushort Flags { get; set; }

        /// <summary>
        /// Server-side transaction timeout in milliseconds; advisory.
        /// </summary>
        public uint Timeout { get; set; }

        /// <summary>
        /// Setup words specific to the Trans1 sub-command (e.g. <c>\PIPE\</c> opcode + FID).
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
        /// Transaction name (e.g. <c>\PIPE\LANMAN</c>). Empty when Trans1 is used as a generic
        /// inter-process call.
        /// </summary>
        public string Name
        {
            get
            {
                return _Name;
            }
            set
            {
                _Name = value ?? throw new ArgumentNullException(nameof(Name), "Name cannot be null.");
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
        /// Serialize the TRANSACTION primary request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Transaction)
            {
                throw new ProtocolValidationException("The SMB1 TRANSACTION request header command must be SMB_COM_TRANSACTION.", nameof(Header));
            }

            if (Setup.Length > byte.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Setup), "SetupCount cannot exceed 255.");
            }

            byte setupCount = (byte)Setup.Length;
            int parameterWordsLength = FixedBaselineParameterWords + (setupCount * sizeof(ushort));
            int parameterCount = Parameters.Length;
            int dataCount = Data.Length;
            bool unicode = (Header.Flags2 & Smb1HeaderFlags2.Unicode) != 0;
            byte[] nameBytes = unicode ? Encoding.Unicode.GetBytes(Name) : Encoding.ASCII.GetBytes(Name);
            byte[] nameTerminator = unicode ? new byte[] { 0, 0 } : new byte[] { 0 };

            int afterByteCount = ProtocolConstants.Smb1HeaderLength + 1 + parameterWordsLength + sizeof(ushort);
            int padBeforeName = unicode ? ((2 - (afterByteCount & 1)) & 1) : 0;
            int afterName = afterByteCount + padBeforeName + nameBytes.Length + nameTerminator.Length;
            int pad1Length = (4 - (afterName & 3)) & 3;
            int parameterOffset = afterName + pad1Length;
            int afterParameters = parameterOffset + parameterCount;
            int pad2Length = (4 - (afterParameters & 3)) & 3;
            int dataOffset = afterParameters + pad2Length;
            int byteCount = padBeforeName + nameBytes.Length + nameTerminator.Length + pad1Length + parameterCount + pad2Length + dataCount;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 TRANSACTION primary-request payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte((byte)(FixedWordCountBaseline + setupCount));
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
            writer.WriteUInt16((ushort)(parameterCount == 0 ? 0 : parameterOffset));
            writer.WriteUInt16((ushort)dataCount);
            writer.WriteUInt16((ushort)(dataCount == 0 ? 0 : dataOffset));
            writer.WriteByte(setupCount);
            writer.WriteByte(0);

            for (int index = 0; index < setupCount; index++)
            {
                writer.WriteUInt16(Setup[index]);
            }

            writer.WriteUInt16((ushort)byteCount);

            for (int index = 0; index < padBeforeName; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(nameBytes);
            writer.WriteBytes(nameTerminator);

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
        /// Parse an SMB1 TRANSACTION primary request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1TransactionRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumBaselineLength = ProtocolConstants.Smb1HeaderLength + 1 + FixedBaselineParameterWords + sizeof(ushort);

            if (buffer.Length < minimumBaselineLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TRANSACTION request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.Transaction)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_TRANSACTION command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount < FixedWordCountBaseline)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION primary request must use WordCount of at least 14.");
            }

            byte declaredSetupCountFromWordCount = (byte)(wordCount - FixedWordCountBaseline);
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

            if (setupCount != declaredSetupCountFromWordCount)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION request SetupCount does not match the WordCount-implied setup-word count.");
            }

            ushort[] setupWords = new ushort[setupCount];

            for (int index = 0; index < setupCount; index++)
            {
                setupWords[index] = reader.ReadUInt16();
            }

            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TRANSACTION request ByteCount does not match the remaining payload length.");
            }

            int payloadAbsoluteStart = ProtocolConstants.Smb1HeaderLength + 1 + (wordCount * sizeof(ushort)) + sizeof(ushort);
            ReadOnlySpan<byte> bufferSpan = buffer.Span;

            byte[] parameters = new byte[parameterCount];
            byte[] data = new byte[dataCount];

            if (parameterCount > 0)
            {
                if (parameterOffset < payloadAbsoluteStart || parameterOffset + parameterCount > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION request ParameterOffset/ParameterCount is invalid.");
                }

                bufferSpan.Slice(parameterOffset, parameterCount).CopyTo(parameters);
            }

            if (dataCount > 0)
            {
                if (dataOffset < payloadAbsoluteStart || dataOffset + dataCount > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB1 TRANSACTION request DataOffset/DataCount is invalid.");
                }

                bufferSpan.Slice(dataOffset, dataCount).CopyTo(data);
            }

            bool unicode = (header.Flags2 & Smb1HeaderFlags2.Unicode) != 0;
            int padBeforeName = unicode ? ((2 - (payloadAbsoluteStart & 1)) & 1) : 0;
            int nameStart = payloadAbsoluteStart + padBeforeName;
            int nameEnd = (parameterCount > 0 ? parameterOffset : (dataCount > 0 ? dataOffset : (payloadAbsoluteStart + byteCount)));
            string name = string.Empty;

            if (nameEnd > nameStart)
            {
                int nameSpan = nameEnd - nameStart;

                if (unicode)
                {
                    int unicodeBytes = 0;

                    while (unicodeBytes + 1 < nameSpan && (bufferSpan[nameStart + unicodeBytes] != 0 || bufferSpan[nameStart + unicodeBytes + 1] != 0))
                    {
                        unicodeBytes += 2;
                    }

                    if (unicodeBytes > 0)
                    {
                        name = Encoding.Unicode.GetString(bufferSpan.Slice(nameStart, unicodeBytes));
                    }
                }
                else
                {
                    int asciiBytes = 0;

                    while (asciiBytes < nameSpan && bufferSpan[nameStart + asciiBytes] != 0)
                    {
                        asciiBytes++;
                    }

                    if (asciiBytes > 0)
                    {
                        name = Encoding.ASCII.GetString(bufferSpan.Slice(nameStart, asciiBytes));
                    }
                }
            }

            return new Smb1TransactionRequest
            {
                Header = header,
                TotalParameterCount = totalParameterCount,
                TotalDataCount = totalDataCount,
                MaxParameterCount = maxParameterCount,
                MaxDataCount = maxDataCount,
                MaxSetupCount = maxSetupCount,
                Flags = flags,
                Timeout = timeout,
                Setup = setupWords,
                Name = name,
                Parameters = parameters,
                Data = data
            };
        }

        private byte[] _Parameters = Array.Empty<byte>();
        private byte[] _Data = Array.Empty<byte>();
        private ushort[] _Setup = Array.Empty<ushort>();
        private string _Name = string.Empty;
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.Transaction,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
