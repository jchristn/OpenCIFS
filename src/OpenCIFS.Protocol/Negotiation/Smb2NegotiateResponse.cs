namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

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
        /// SMB 3.1.1-style negotiate-context count carried by an SMB 3.1.1 response.
        /// </summary>
        public ushort NegotiateContextCount { get; set; }

        /// <summary>
        /// SMB 3.1.1-style negotiate-context absolute offset carried by an SMB 3.1.1 response.
        /// </summary>
        public uint NegotiateContextOffset { get; set; }

        /// <summary>
        /// Optional raw negotiate-context bytes carried by an SMB 3.1.1-style response.
        /// </summary>
        public byte[] NegotiateContextData
        {
            get
            {
                return _NegotiateContextData;
            }
            set
            {
                _NegotiateContextData = value ?? throw new ArgumentNullException(nameof(NegotiateContextData), "NegotiateContextData cannot be null.");
            }
        }

        /// <summary>
        /// Decode the carried SMB 3.1.1 negotiate-context list as typed entries.
        /// </summary>
        /// <returns>Typed negotiate-context entries, or an empty array when none are carried.</returns>
        public Smb2NegotiateContextEntry[] DecodeNegotiateContextEntries()
        {
            if (NegotiateContextCount == 0 || NegotiateContextData.Length == 0)
            {
                return Array.Empty<Smb2NegotiateContextEntry>();
            }

            return Smb2NegotiateContextList.Decode(NegotiateContextData, NegotiateContextCount);
        }

        /// <summary>
        /// Set the SMB 3.1.1 negotiate-context list from typed entries and update the carried context count and bytes.
        /// </summary>
        /// <param name="entries">Typed negotiate-context entries.</param>
        public void SetNegotiateContextEntries(IReadOnlyList<Smb2NegotiateContextEntry> entries)
        {
            if (entries == null)
            {
                throw new ArgumentNullException(nameof(entries), "Entries cannot be null.");
            }

            if (entries.Count > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(entries), "Entries cannot exceed 65535 contexts.");
            }

            NegotiateContextCount = (ushort)entries.Count;
            NegotiateContextData = entries.Count == 0
                ? Array.Empty<byte>()
                : Smb2NegotiateContextList.Encode(entries);
        }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            bool carriesSmb311Shape = Dialect == SmbDialect.Smb311;
            bool carriesContexts = carriesSmb311Shape && (NegotiateContextCount != 0 || NegotiateContextData.Length != 0);
            ushort securityBufferOffset = SecurityBuffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);
            uint negotiateContextOffset = 0;

            if (carriesContexts)
            {
                int unalignedAbsoluteContextOffset = ProtocolConstants.Smb2HeaderLength + FixedBodyLength + SecurityBuffer.Length;
                negotiateContextOffset = (uint)AlignToEight(unalignedAbsoluteContextOffset);
            }

            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)SecurityMode);
            writer.WriteUInt16(SmbDialectCatalog.ToSmb2WireDialect(Dialect));
            writer.WriteUInt16(carriesSmb311Shape ? NegotiateContextCount : (ushort)0);
            writer.WriteBytes(ServerGuid.ToByteArray());
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteUInt32(MaxTransactSize);
            writer.WriteUInt32(MaxReadSize);
            writer.WriteUInt32(MaxWriteSize);
            writer.WriteUInt64(SystemTime);
            writer.WriteUInt64(ServerStartTime);
            writer.WriteUInt16(securityBufferOffset);
            writer.WriteUInt16((ushort)SecurityBuffer.Length);
            writer.WriteUInt32(carriesSmb311Shape ? negotiateContextOffset : 0U);
            writer.WriteBytes(SecurityBuffer);

            if (carriesContexts)
            {
                int currentAbsoluteOffset = ProtocolConstants.Smb2HeaderLength + writer.Length;
                int paddingLength = (int)negotiateContextOffset - currentAbsoluteOffset;

                for (int index = 0; index < paddingLength; index++)
                {
                    writer.WriteByte(0);
                }

                writer.WriteBytes(NegotiateContextData);
            }

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
            ushort negotiateContextCount = reader.ReadUInt16();
            response.ServerGuid = new Guid(reader.ReadBytes(16));
            response.Capabilities = (Smb2GlobalCapabilities)reader.ReadUInt32();
            response.MaxTransactSize = reader.ReadUInt32();
            response.MaxReadSize = reader.ReadUInt32();
            response.MaxWriteSize = reader.ReadUInt32();
            response.SystemTime = reader.ReadUInt64();
            response.ServerStartTime = reader.ReadUInt64();
            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();
            uint negotiateContextOffset = reader.ReadUInt32();
            bool carriesSmb311Shape = dialect == SmbDialect.Smb311;

            if (carriesSmb311Shape)
            {
                response.NegotiateContextCount = negotiateContextCount;
                response.NegotiateContextOffset = negotiateContextOffset;
            }

            if (securityBufferLength != 0)
            {
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
            }
            else
            {
                response.SecurityBuffer = Array.Empty<byte>();
            }

            if (carriesSmb311Shape && negotiateContextCount != 0)
            {
                if (negotiateContextOffset > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB 3.1.1 negotiate-context offset is malformed.");
                }

                int relativeNegotiateContextOffset = checked((int)negotiateContextOffset - ProtocolConstants.Smb2HeaderLength);

                if (relativeNegotiateContextOffset < FixedBodyLength || relativeNegotiateContextOffset > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB 3.1.1 negotiate-context offset is malformed.");
                }

                response.NegotiateContextData = buffer.Slice(relativeNegotiateContextOffset).ToArray();
            }
            else if (!carriesSmb311Shape && securityBufferLength == 0 && reader.RemainingBytes != 0)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate response contains trailing bytes without a security buffer length.");
            }

            return response;
        }

        private byte[] _SecurityBuffer = Array.Empty<byte>();
        private byte[] _NegotiateContextData = Array.Empty<byte>();

        private static int AlignToEight(int value)
        {
            int remainder = value % 8;
            return remainder == 0
                ? value
                : value + (8 - remainder);
        }
    }
}
