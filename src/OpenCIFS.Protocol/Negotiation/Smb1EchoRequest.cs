namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_ECHO</c> request used to ping the server and exercise the read path.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.39.1. The request carries WordCount=1 (EchoCount as a USHORT) and a
    /// variable-length ByteCount-prefixed buffer that the server echoes back EchoCount times.
    /// </remarks>
    public sealed class Smb1EchoRequest
    {
        private const byte WordCountValue = 0x01;
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
        /// Number of echo responses the server should emit. Must be at least one.
        /// </summary>
        public ushort EchoCount { get; set; } = 1;

        /// <summary>
        /// Echo payload that the server returns verbatim.
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
        /// Serialize the ECHO request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Echo)
            {
                throw new ProtocolValidationException("The SMB1 ECHO request header command must be SMB_COM_ECHO.", nameof(Header));
            }

            if (Data.Length > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Data), "SMB1 ECHO request payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(EchoCount);
            writer.WriteUInt16((ushort)Data.Length);
            writer.WriteBytes(Data);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 ECHO request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1EchoRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 ECHO request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.Echo)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_ECHO command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 ECHO request must use WordCount=1.");
            }

            ushort echoCount = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 ECHO request ByteCount does not match the remaining payload length.");
            }

            byte[] data = reader.ReadBytes(byteCount);

            return new Smb1EchoRequest
            {
                Header = header,
                EchoCount = echoCount,
                Data = data
            };
        }

        private byte[] _Data = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.Echo,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
