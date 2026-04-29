namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 negotiate response payload.
    /// </summary>
    public sealed class Smb2NegotiateResponse
    {
        private const ushort StructureSize = 65;
        private const ushort FixedBodyLength = 64;

        /// <summary>
        /// Negotiated security-mode flags.
        /// </summary>
        public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        /// <summary>
        /// Negotiated dialect.
        /// </summary>
        public SmbDialect Dialect { get; set; } = SmbDialect.Smb2002;

        /// <summary>
        /// Server GUID.
        /// </summary>
        public Guid ServerGuid { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Negotiated global capabilities.
        /// </summary>
        public Smb2GlobalCapabilities Capabilities { get; set; } = Smb2GlobalCapabilities.None;

        /// <summary>
        /// Maximum transact size.
        /// </summary>
        public uint MaxTransactSize { get; set; } = 65536;

        /// <summary>
        /// Maximum read size.
        /// </summary>
        public uint MaxReadSize { get; set; } = 65536;

        /// <summary>
        /// Maximum write size.
        /// </summary>
        public uint MaxWriteSize { get; set; } = 65536;

        /// <summary>
        /// Current server time in FILETIME form.
        /// </summary>
        public ulong SystemTime { get; set; }

        /// <summary>
        /// Server start time in FILETIME form.
        /// </summary>
        public ulong ServerStartTime { get; set; }

        /// <summary>
        /// Security blob bytes.
        /// </summary>
        public byte[] SecurityBuffer
        {
            get
            {
                return _SecurityBuffer;
            }
            set
            {
                _SecurityBuffer = value ?? throw new ArgumentNullException(nameof(SecurityBuffer), "SecurityBuffer cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            ushort securityBufferOffset = SecurityBuffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)SecurityMode);
            writer.WriteUInt16(SmbDialectCatalog.ToSmb2WireDialect(Dialect));
            writer.WriteUInt16(0);
            writer.WriteBytes(ServerGuid.ToByteArray());
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteUInt32(MaxTransactSize);
            writer.WriteUInt32(MaxReadSize);
            writer.WriteUInt32(MaxWriteSize);
            writer.WriteUInt64(SystemTime);
            writer.WriteUInt64(ServerStartTime);
            writer.WriteUInt16(securityBufferOffset);
            writer.WriteUInt16((ushort)SecurityBuffer.Length);
            writer.WriteUInt32(0);
            writer.WriteBytes(SecurityBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2NegotiateResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 negotiate response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate response structure size must be 65 bytes.");
            }

            Smb2NegotiateResponse response = new Smb2NegotiateResponse
            {
                SecurityMode = (Smb2SecurityMode)reader.ReadUInt16()
            };

            ushort wireDialect = reader.ReadUInt16();

            if (!SmbDialectCatalog.TryFromSmb2WireDialect(wireDialect, out SmbDialect dialect))
            {
                throw new ProtocolEncodingException("The SMB2 negotiate response contains an unknown dialect value.");
            }

            response.Dialect = dialect;
            reader.Skip(2);
            response.ServerGuid = new Guid(reader.ReadBytes(16));
            response.Capabilities = (Smb2GlobalCapabilities)reader.ReadUInt32();
            response.MaxTransactSize = reader.ReadUInt32();
            response.MaxReadSize = reader.ReadUInt32();
            response.MaxWriteSize = reader.ReadUInt32();
            response.SystemTime = reader.ReadUInt64();
            response.ServerStartTime = reader.ReadUInt64();
            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();
            reader.Skip(4);

            if (securityBufferLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 negotiate response contains trailing bytes without a security buffer length.");
                }

                response.SecurityBuffer = Array.Empty<byte>();
                return response;
            }

            int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativeSecurityBufferOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate response security-buffer offset is invalid.");
            }

            if (relativeSecurityBufferOffset + securityBufferLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate response security buffer exceeds the available payload.");
            }

            response.SecurityBuffer = buffer.Slice(relativeSecurityBufferOffset, securityBufferLength).ToArray();
            return response;
        }

        private byte[] _SecurityBuffer = Array.Empty<byte>();
    }
}
