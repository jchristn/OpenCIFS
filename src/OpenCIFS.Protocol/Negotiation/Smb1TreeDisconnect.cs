namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_TREE_DISCONNECT</c> request and response.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.51.1 / 2.2.4.51.2. Both the request and response carry WordCount=0
    /// and ByteCount=0 with no payload. Used by both client (request) and server (response) sides.
    /// </remarks>
    public sealed class Smb1TreeDisconnect
    {
        private const byte WordCountValue = 0x00;
        private const int FixedBodyLength = 1 + sizeof(ushort);

        /// <summary>
        /// SMB1 header.
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
        /// Serialize the TREE_DISCONNECT message to its SMB1 wire format.
        /// </summary>
        /// <returns>Message bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.TreeDisconnect)
            {
                throw new ProtocolValidationException("The SMB1 TREE_DISCONNECT header command must be SMB_COM_TREE_DISCONNECT.", nameof(Header));
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 TREE_DISCONNECT message from its wire bytes.
        /// </summary>
        /// <param name="buffer">Message bytes.</param>
        /// <returns>Parsed message.</returns>
        public static Smb1TreeDisconnect ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 TREE_DISCONNECT message.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.TreeDisconnect)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_TREE_DISCONNECT command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 TREE_DISCONNECT message must use WordCount=0.");
            }

            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 TREE_DISCONNECT message must use ByteCount=0.");
            }

            return new Smb1TreeDisconnect
            {
                Header = header
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.TreeDisconnect,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
