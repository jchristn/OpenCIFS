namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_TREE_CONNECT_ANDX</c> request used to bind a session to a share.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.55.2. The bounded codec only supports the SMB 3.1.1-era Unicode strings
    /// convention (<see cref="Smb1HeaderFlags2.Unicode" /> set on the carrying header) for the path
    /// while the service string remains ASCII per spec.
    /// </remarks>
    public sealed class Smb1TreeConnectAndXRequest
    {
        private const byte WordCountValue = 0x04;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;
        private static readonly int DataSectionStartOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

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
        /// Tree-connect flags. Bit 0 = disconnect prior tree.
        /// </summary>
        public ushort Flags { get; set; }

        /// <summary>
        /// Password bytes carried by the request. Empty for extended-security session bindings.
        /// </summary>
        public byte[] Password
        {
            get
            {
                return _Password;
            }
            set
            {
                _Password = value ?? throw new ArgumentNullException(nameof(Password), "Password cannot be null.");
            }
        }

        /// <summary>
        /// Share path in <c>\\server\share</c> form. Encoded as Unicode on the wire.
        /// </summary>
        public string Path
        {
            get
            {
                return _Path;
            }
            set
            {
                _Path = value ?? throw new ArgumentNullException(nameof(Path), "Path cannot be null.");
            }
        }

        /// <summary>
        /// Service string. ASCII on the wire. Common values: <c>?????</c>, <c>A:</c>, <c>IPC</c>, <c>LPT1:</c>.
        /// </summary>
        public string Service
        {
            get
            {
                return _Service;
            }
            set
            {
                _Service = value ?? throw new ArgumentNullException(nameof(Service), "Service cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            EnsureUnicodeShape();
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.TreeConnectAndX)
            {
                throw new ProtocolValidationException("The SMB1 TREE_CONNECT_ANDX request header command must be SMB_COM_TREE_CONNECT_ANDX.", nameof(Header));
            }

            byte[] passwordBytes = Password;
            byte[] pathBytes = EncodeUnicodeNullTerminatedString(Path);
            byte[] serviceBytes = EncodeAsciiNullTerminatedString(Service);
            int padLength = ((DataSectionStartOffset + passwordBytes.Length) & 1) == 0 ? 0 : 1;
            int byteCount = passwordBytes.Length + padLength + pathBytes.Length + serviceBytes.Length;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Path), "SMB1 TREE_CONNECT_ANDX request payload exceeds the 16-bit ByteCount field.");
            }

            if (passwordBytes.Length > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Password), "SMB1 TREE_CONNECT_ANDX password exceeds the 16-bit length field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(Flags);
            writer.WriteUInt16((ushort)passwordBytes.Length);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteBytes(passwordBytes);

            for (int index = 0; index < padLength; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(pathBytes);
            writer.WriteBytes(serviceBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 TREE_CONNECT_ANDX request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1TreeConnectAndXRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TREE_CONNECT_ANDX request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.TreeConnectAndX)
            {
                throw new ProtocolEncodingException("The SMB1 request does not carry an SMB_COM_TREE_CONNECT_ANDX command.");
            }

            if ((header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TREE_CONNECT_ANDX codec only supports Unicode strings.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TREE_CONNECT_ANDX request codec requires WordCount=4.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort flags = reader.ReadUInt16();
            ushort passwordLength = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TREE_CONNECT_ANDX request ByteCount does not match the remaining payload length.");
            }

            byte[] passwordBytes = reader.ReadBytes(passwordLength);
            int padLength = ((DataSectionStartOffset + passwordLength) & 1) == 0 ? 0 : 1;

            if (padLength > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TREE_CONNECT_ANDX request payload is missing the Unicode alignment pad.");
            }

            reader.Skip(padLength);
            string path = ReadUnicodeNullTerminatedString(ref reader, "Path");
            string service = ReadAsciiNullTerminatedString(ref reader, "Service");

            return new Smb1TreeConnectAndXRequest
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                Flags = flags,
                Password = passwordBytes,
                Path = path,
                Service = service
            };
        }

        private void EnsureUnicodeShape()
        {
            if ((Header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolValidationException("The bounded SMB1 TREE_CONNECT_ANDX codec only supports Unicode strings.", nameof(Header));
            }
        }

        private static byte[] EncodeUnicodeNullTerminatedString(string value)
        {
            byte[] textBytes = Encoding.Unicode.GetBytes(value);
            byte[] result = new byte[textBytes.Length + 2];
            Buffer.BlockCopy(textBytes, 0, result, 0, textBytes.Length);
            return result;
        }

        private static byte[] EncodeAsciiNullTerminatedString(string value)
        {
            byte[] textBytes = Encoding.ASCII.GetBytes(value);
            byte[] result = new byte[textBytes.Length + 1];
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

            throw new ProtocolEncodingException("The SMB1 TREE_CONNECT_ANDX " + fieldName + " string is not null-terminated.");
        }

        private static string ReadAsciiNullTerminatedString(ref LittleEndianReader reader, string fieldName)
        {
            List<byte> charBytes = new List<byte>();

            while (reader.RemainingBytes >= 1)
            {
                byte value = reader.ReadByte();

                if (value == 0)
                {
                    return Encoding.ASCII.GetString(charBytes.ToArray());
                }

                charBytes.Add(value);
            }

            throw new ProtocolEncodingException("The SMB1 TREE_CONNECT_ANDX " + fieldName + " string is not null-terminated.");
        }

        private byte[] _Password = Array.Empty<byte>();
        private string _Path = string.Empty;
        private string _Service = "?????";
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.TreeConnectAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
