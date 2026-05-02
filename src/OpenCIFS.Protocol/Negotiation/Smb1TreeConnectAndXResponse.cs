namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// SMB1 <c>SMB_COM_TREE_CONNECT_ANDX</c> response in the extended NT WordCount=7 shape.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.55.2. The bounded codec only supports the SMB 3.1.1-era Unicode strings
    /// convention (<see cref="Smb1HeaderFlags2.Unicode" /> set on the carrying header) for the
    /// NativeFileSystem string while the service string remains ASCII per spec.
    /// </remarks>
    public sealed class Smb1TreeConnectAndXResponse
    {
        private const byte WordCountValue = 0x07;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;
        private static readonly int DataSectionStartOffset = ProtocolConstants.Smb1HeaderLength + 1 + ParameterWordsLength + sizeof(ushort);

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
        /// Trailing AndX command code, or <c>0xFF</c> when no further command follows.
        /// </summary>
        public byte AndXCommand { get; set; } = AndXNoFurtherCommands;

        /// <summary>
        /// AndX offset relative to the SMB header start, in bytes.
        /// </summary>
        public ushort AndXOffset { get; set; }

        /// <summary>
        /// Optional support flags. Bit 0 = SMB_SUPPORT_SEARCH_BITS, bit 1 = SMB_SHARE_IS_IN_DFS, etc.
        /// </summary>
        public ushort OptionalSupport { get; set; }

        /// <summary>
        /// Maximal share access rights granted to the caller's authenticated session.
        /// </summary>
        public uint MaximalShareAccessRights { get; set; }

        /// <summary>
        /// Maximal share access rights granted to a guest session against this share.
        /// </summary>
        public uint GuestMaximalShareAccessRights { get; set; }

        /// <summary>
        /// Service string echoed by the server. ASCII on the wire.
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
        /// Native filesystem name. Unicode on the wire when the carrying header has Unicode set.
        /// </summary>
        public string NativeFileSystem
        {
            get
            {
                return _NativeFileSystem;
            }
            set
            {
                _NativeFileSystem = value ?? throw new ArgumentNullException(nameof(NativeFileSystem), "NativeFileSystem cannot be null.");
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

            if (Header.Command != Smb1Command.TreeConnectAndX)
            {
                throw new ProtocolValidationException("The SMB1 TREE_CONNECT_ANDX response header command must be SMB_COM_TREE_CONNECT_ANDX.", nameof(Header));
            }

            byte[] serviceBytes = EncodeAsciiNullTerminatedString(Service);
            int padLength = ((DataSectionStartOffset + serviceBytes.Length) & 1) == 0 ? 0 : 1;
            byte[] nativeFileSystemBytes = EncodeUnicodeNullTerminatedString(NativeFileSystem);
            int byteCount = serviceBytes.Length + padLength + nativeFileSystemBytes.Length;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(NativeFileSystem), "SMB1 TREE_CONNECT_ANDX response payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(OptionalSupport);
            writer.WriteUInt32(MaximalShareAccessRights);
            writer.WriteUInt32(GuestMaximalShareAccessRights);
            writer.WriteUInt16((ushort)byteCount);
            writer.WriteBytes(serviceBytes);

            for (int index = 0; index < padLength; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(nativeFileSystemBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 TREE_CONNECT_ANDX response from its wire bytes for the WordCount=7 extended shape.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb1TreeConnectAndXResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TREE_CONNECT_ANDX response.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.TreeConnectAndX)
            {
                throw new ProtocolEncodingException("The SMB1 response does not carry an SMB_COM_TREE_CONNECT_ANDX command.");
            }

            if ((header.Flags2 & Smb1HeaderFlags2.Unicode) == 0)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TREE_CONNECT_ANDX codec only supports Unicode strings.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The bounded SMB1 TREE_CONNECT_ANDX response codec requires WordCount=7.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort optionalSupport = reader.ReadUInt16();
            uint maximalShareAccessRights = reader.ReadUInt32();
            uint guestMaximalShareAccessRights = reader.ReadUInt32();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TREE_CONNECT_ANDX response ByteCount does not match the remaining payload length.");
            }

            string service = ReadAsciiNullTerminatedString(ref reader, "Service");
            int serviceConsumed = Encoding.ASCII.GetByteCount(service) + 1;
            int padLength = ((DataSectionStartOffset + serviceConsumed) & 1) == 0 ? 0 : 1;

            if (padLength > reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 TREE_CONNECT_ANDX response payload is missing the Unicode alignment pad.");
            }

            reader.Skip(padLength);
            string nativeFileSystem = ReadUnicodeNullTerminatedString(ref reader, "NativeFileSystem");

            return new Smb1TreeConnectAndXResponse
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                OptionalSupport = optionalSupport,
                MaximalShareAccessRights = maximalShareAccessRights,
                GuestMaximalShareAccessRights = guestMaximalShareAccessRights,
                Service = service,
                NativeFileSystem = nativeFileSystem
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

        private string _Service = "?????";
        private string _NativeFileSystem = "NTFS";
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.TreeConnectAndX,
            Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
