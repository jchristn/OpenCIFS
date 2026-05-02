namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_SESSION_SETUP_ANDX</c> response for the NT LM 0.12 extended-security shape.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.6.2 (extended-security variant). The bounded codec only supports
    /// the SMB 3.1.1-era Unicode strings convention (<see cref="Smb1HeaderFlags2.Unicode" /> set on
    /// the carrying header). Server emits an SPNEGO response blob plus NativeOS, NativeLanMan, and
    /// PrimaryDomain Unicode strings in the data section.
    /// </remarks>
    public sealed class Smb1SessionSetupAndXResponse
    {
        private const byte WordCountValue = 0x04;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;

        /// <summary>
        /// Action bit indicating the server logged the client on as guest.
        /// </summary>
        public const ushort GuestLogonActionBit = 0x0001;

        private static readonly int DataSectionStartOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

        /// <summary>
        /// SMB1 response header. Must have <see cref="Smb1HeaderFlags2.Unicode" /> set for the bounded slice.
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
        /// Action flags. Bit <see cref="GuestLogonActionBit" /> indicates the client was authenticated as guest.
        /// </summary>
        public ushort Action { get; set; }

        /// <summary>
        /// SPNEGO response blob carried by the response.
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
        /// Native OS string identifying the server OS.
        /// </summary>
        public string NativeOS { get; set; } = "Windows";

        /// <summary>
        /// Native LAN-manager string identifying the server.
        /// </summary>
        public string NativeLanMan { get; set; } = "OpenCIFS";

        /// <summary>
        /// Primary domain string the server is a member of.
        /// </summary>
        public string PrimaryDomain { get; set; } = "WORKGROUP";

        /// <summary>
        /// Whether the response indicates a guest logon.
        /// </summary>
        public bool IsGuestLogon
        {
            get
            {
                return (Action & GuestLogonActionBit) != 0;
            }
        }

        /// <summary>
        /// Serialize the response to its SMB1 wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            EnsureUnicodeShape();
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.SessionSetupAndX)
            {
                throw new ProtocolValidationException("The SMB1 SESSION_SETUP_ANDX response header command must be SMB_COM_SESSION_SETUP_ANDX.", nameof(Header));
            }

            byte[] securityBlobBytes = SecurityBlob;
            byte[] nativeOSBytes = EncodeUnicodeNullTerminatedString(NativeOS);
            byte[] nativeLanManBytes = EncodeUnicodeNullTerminatedString(NativeLanMan);
            byte[] primaryDomainBytes = EncodeUnicodeNullTerminatedString(PrimaryDomain);
            int padLength = ((DataSectionStartOffset + securityBlobBytes.Length) & 1) == 0 ? 0 : 1;
            int byteCount = securityBlobBytes.Length + padLength + nativeOSBytes.Length + nativeLanManBytes.Length + primaryDomainBytes.Length;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(SecurityBlob), "SMB1 SESSION_SETUP_ANDX response payload exceeds the 16-bit ByteCount field.");
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
            writer.WriteUInt16(Action);
            writer.WriteUInt16((ushort)securityBlobBytes.Length);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteBytes(securityBlobBytes);

            for (int index = 0; index < padLength; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(nativeOSBytes);
            writer.WriteBytes(nativeLanManBytes);
            writer.WriteBytes(primaryDomainBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 SESSION_SETUP_ANDX response from its wire bytes for the extended-security shape.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1SessionSetupAndXResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 SESSION_SETUP_ANDX response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.SessionSetupAndX)
            {
                throw new ProtocolEncodingException("The SMB1 response does not carry an SMB_COM_SESSION_SETUP_ANDX command.");
            }

            if ((header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolEncodingException("The bounded SMB1 SESSION_SETUP_ANDX codec only supports Unicode strings.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 SESSION_SETUP_ANDX response codec requires WordCount=4 (extended-security shape).");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort action = reader.ReadUInt16();
            ushort securityBlobLength = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 SESSION_SETUP_ANDX response ByteCount does not match the remaining payload length.");
            }

            byte[] securityBlobBytes = reader.ReadBytes(securityBlobLength);
            int padLength = ((DataSectionStartOffset + securityBlobLength) & 1) == 0 ? 0 : 1;

            if (padLength > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 SESSION_SETUP_ANDX response payload is missing the Unicode alignment pad.");
            }

            reader.Skip(padLength);
            string nativeOS = ReadUnicodeNullTerminatedString(ref reader, "NativeOS");
            string nativeLanMan = ReadUnicodeNullTerminatedString(ref reader, "NativeLanMan");
            string primaryDomain = ReadUnicodeNullTerminatedString(ref reader, "PrimaryDomain");

            return new Smb1SessionSetupAndXResponse
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                Action = action,
                SecurityBlob = securityBlobBytes,
                NativeOS = nativeOS,
                NativeLanMan = nativeLanMan,
                PrimaryDomain = primaryDomain
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
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
