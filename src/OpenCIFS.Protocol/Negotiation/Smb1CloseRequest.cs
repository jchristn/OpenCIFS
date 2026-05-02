namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 <c>SMB_COM_CLOSE</c> request used to release a file ID against the server.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.5.1. The request carries WordCount=3 (FID and LastWriteTime as a UTIME)
    /// with ByteCount=0 and no buffer payload. The response shape is captured in
    /// <see cref="Smb1CloseResponse" />.
    /// </remarks>
    public sealed class Smb1CloseRequest
    {
        private const byte WordCountValue = 0x03;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);

        /// <summary>
        /// Sentinel UTIME value indicating that the server should not update the modification time.
        /// </summary>
        public const uint LastWriteTimeUnchanged = 0xFFFFFFFFU;

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
        /// SMB1 file identifier returned by the prior open request.
        /// </summary>
        public ushort FileId { get; set; }

        /// <summary>
        /// Modification time as a UTIME (seconds since 1970-01-01 UTC), or
        /// <see cref="LastWriteTimeUnchanged" /> to leave the value as-is.
        /// </summary>
        public uint LastWriteTime { get; set; } = LastWriteTimeUnchanged;

        /// <summary>
        /// Serialize the CLOSE request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.Close)
            {
                throw new ProtocolValidationException("The SMB1 CLOSE request header command must be SMB_COM_CLOSE.", nameof(Header));
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteUInt16(FileId);
            writer.WriteUInt32(LastWriteTime);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 CLOSE request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1CloseRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 CLOSE request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.Close)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_CLOSE command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 CLOSE request must use WordCount=3.");
            }

            ushort fileId = reader.ReadUInt16();
            uint lastWriteTime = reader.ReadUInt32();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != 0)
            {
                throw new ProtocolEncodingException("The SMB1 CLOSE request must use ByteCount=0.");
            }

            return new Smb1CloseRequest
            {
                Header = header,
                FileId = fileId,
                LastWriteTime = lastWriteTime
            };
        }

        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.Close,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
