namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_SESSION_SETUP_ANDX</c> request for the NT LM 0.12 extended-security shape.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.6.2 (extended-security variant). The bounded codec only supports
    /// the SMB 3.1.1-era Unicode strings convention (<see cref="Smb1HeaderFlags2.Unicode" /> set on
    /// the carrying header).
    /// </remarks>
    public sealed class Smb1SessionSetupAndXRequest
    {
        private const byte WordCountValue = 0x0C;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;
        private static readonly int DataSectionStartOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

        /// <summary>
        /// SMB1 request header. Must have <see cref="Smb1HeaderFlags2.Unicode" /> set for the bounded slice.
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
        /// Maximum buffer size accepted by the client.
        /// </summary>
        public ushort MaxBufferSize { get; set; } = 65535;

        /// <summary>
        /// Maximum number of pending multiplexed requests on the connection.
        /// </summary>
        public ushort MaxMpxCount { get; set; } = 50;

        /// <summary>
        /// Virtual circuit index. <c>0</c> requests a fresh session.
        /// </summary>
        public ushort VcNumber { get; set; }

        /// <summary>
        /// Session key seed echoed from the server's NEGOTIATE response, or <c>0</c> on initial setup.
        /// </summary>
        public uint SessionKey { get; set; }

        /// <summary>
        /// Client capability flags.
        /// </summary>
        public Smb1Capabilities Capabilities { get; set; } = Smb1Capabilities.Unicode | Smb1Capabilities.LargeFiles | Smb1Capabilities.NtSmbs | Smb1Capabilities.RpcRemoteApis | Smb1Capabilities.Status32 | Smb1Capabilities.NtFind | Smb1Capabilities.LargeReadX | Smb1Capabilities.LargeWriteX | Smb1Capabilities.ExtendedSecurity;

        /// <summary>
        /// SPNEGO security blob carried by the request.
        /// </summary>
        public byte[] SecurityBlob
        {
            get
            {
                return _SecurityBlob;
            }
            set
            {
                _SecurityBlob = value ?? throw new ArgumentNullException(nameof(SecurityBlob), "SecurityBlob cannot be null.");
            }
        }

        /// <summary>
        /// Native OS string identifying the client OS.
        /// </summary>
        public string NativeOS { get; set; } = "Windows";

        /// <summary>
        /// Native LAN-manager string identifying the client redirector.
        /// </summary>
        public string NativeLanMan { get; set; } = "OpenCIFS";

        /// <summary>
        /// Serialize the request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            EnsureUnicodeShape();
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.SessionSetupAndX)
            {
                throw new ProtocolValidationException("The SMB1 SESSION_SETUP_ANDX request header command must be SMB_COM_SESSION_SETUP_ANDX.", nameof(Header));
            }

            byte[] securityBlobBytes = SecurityBlob;
            byte[] nativeOSBytes = EncodeUnicodeNullTerminatedString(NativeOS);
            byte[] nativeLanManBytes = EncodeUnicodeNullTerminatedString(NativeLanMan);
            int padLength = ((DataSectionStartOffset + securityBlobBytes.Length) & 1) == 0 ? 0 : 1;
            int byteCount = securityBlobBytes.Length + padLength + nativeOSBytes.Length + nativeLanManBytes.Length;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(SecurityBlob), "SMB1 SESSION_SETUP_ANDX request payload exceeds the 16-bit ByteCount field.");
            }

            if (securityBlobBytes.Length > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(SecurityBlob), "SMB1 SESSION_SETUP_ANDX SecurityBlob exceeds the 16-bit length field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(MaxBufferSize);
            writer.WriteUInt16(MaxMpxCount);
            writer.WriteUInt16(VcNumber);
            writer.WriteUInt32(SessionKey);
            writer.WriteUInt16((ushort)securityBlobBytes.Length);
            writer.WriteUInt32(0);
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteBytes(securityBlobBytes);

            for (int index = 0; index < padLength; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(nativeOSBytes);
            writer.WriteBytes(nativeLanManBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 SESSION_SETUP_ANDX request from its wire bytes for the extended-security shape.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1SessionSetupAndXRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 SESSION_SETUP_ANDX request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.SessionSetupAndX)
            {
                throw new ProtocolEncodingException("The SMB1 request does not carry an SMB_COM_SESSION_SETUP_ANDX command.");
            }

            if ((header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolEncodingException("The bounded SMB1 SESSION_SETUP_ANDX codec only supports Unicode strings.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 SESSION_SETUP_ANDX request codec requires WordCount=12 (extended-security shape).");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort maxBufferSize = reader.ReadUInt16();
            ushort maxMpxCount = reader.ReadUInt16();
            ushort vcNumber = reader.ReadUInt16();
            uint sessionKey = reader.ReadUInt32();
            ushort securityBlobLength = reader.ReadUInt16();
            reader.Skip(4);
            uint capabilities = reader.ReadUInt32();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 SESSION_SETUP_ANDX request ByteCount does not match the remaining payload length.");
            }

            byte[] securityBlobBytes = reader.ReadBytes(securityBlobLength);
            int padLength = ((DataSectionStartOffset + securityBlobLength) & 1) == 0 ? 0 : 1;

            if (padLength > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 SESSION_SETUP_ANDX request payload is missing the Unicode alignment pad.");
            }

            reader.Skip(padLength);
            string nativeOS = ReadUnicodeNullTerminatedString(ref reader, "NativeOS");
            string nativeLanMan = ReadUnicodeNullTerminatedString(ref reader, "NativeLanMan");

            return new Smb1SessionSetupAndXRequest
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                MaxBufferSize = maxBufferSize,
                MaxMpxCount = maxMpxCount,
                VcNumber = vcNumber,
                SessionKey = sessionKey,
                Capabilities = (Smb1Capabilities)capabilities,
                SecurityBlob = securityBlobBytes,
                NativeOS = nativeOS,
                NativeLanMan = nativeLanMan
            };
        }

        private void EnsureUnicodeShape()
        {
            if ((Header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolValidationException("The bounded SMB1 SESSION_SETUP_ANDX codec only supports Unicode strings.", nameof(Header));
            }
        }

        private static byte[] EncodeUnicodeNullTerminatedString(string value)
        {
            string nonNull = value ?? string.Empty;
            byte[] textBytes = Encoding.Unicode.GetBytes(nonNull);
            byte[] result = new byte[textBytes.Length + 2];
            Buffer.BlockCopy(textBytes, 0, result, 0, textBytes.Length);
            return result;
        }

        private static string ReadUnicodeNullTerminatedString(ref LittleEndianReader reader, string fieldName)
        {
            List<byte> charBytes = new List<byte>();

            while (reader.RemainingBytes >= 2)
            {
                byte low = reader.ReadByte();
                byte high = reader.ReadByte();

                if (low == 0 && high == 0)
                {
                    return Encoding.Unicode.GetString(charBytes.ToArray());
                }

                charBytes.Add(low);
                charBytes.Add(high);
            }

            throw new ProtocolEncodingException("The SMB1 SESSION_SETUP_ANDX " + fieldName + " string is not null-terminated.");
        }

        private byte[] _SecurityBlob = Array.Empty<byte>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.SessionSetupAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
