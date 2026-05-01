namespace OpenCIFS.Protocol
{
    using System;
    using System.Buffers.Binary;
    using System.Collections.Generic;

    /// <summary>
    /// SMB2 negotiate request payload.
    /// </summary>
    public sealed class Smb2NegotiateRequest
    {
        private const ushort StructureSize = 36;
        private const int FixedHeaderLength = 36;

        /// <summary>
        /// Requested security-mode flags.
        /// </summary>
        public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        /// <summary>
        /// Client global capabilities.
        /// </summary>
        public Smb2GlobalCapabilities Capabilities { get; set; } = Smb2GlobalCapabilities.None;

        /// <summary>
        /// Client GUID.
        /// </summary>
        public Guid ClientGuid { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Client start time in FILETIME form for SMB 2.0.2 style negotiation.
        /// </summary>
        public ulong ClientStartTime { get; set; }

        /// <summary>
        /// Client-offered SMB2/3 dialects.
        /// </summary>
        public SmbDialect[] Dialects
        {
            get
            {
                return _Dialects;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Dialects), "Dialects cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(Dialects), "At least one dialect must be supplied.");
                }

                _Dialects = value;
            }
        }

        /// <summary>
        /// Optional SMB 3.1.1-style negotiate-context offset as received on the wire.
        /// This is preserved only so older dialect handlers can tolerate newer request shapes.
        /// </summary>
        public uint NegotiateContextOffset { get; set; }

        /// <summary>
        /// Optional SMB 3.1.1-style negotiate-context count as received on the wire.
        /// This is preserved only so older dialect handlers can tolerate newer request shapes.
        /// </summary>
        public ushort NegotiateContextCount { get; set; }

        /// <summary>
        /// Optional raw negotiate-context bytes carried by an SMB 3.1.1-style request.
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
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)Dialects.Length);
            writer.WriteUInt16((ushort)SecurityMode);
            writer.WriteUInt16(0);
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteBytes(ClientGuid.ToByteArray());
            bool carriesSmb311Shape = Array.IndexOf(Dialects, SmbDialect.Smb311) >= 0;

            if (carriesSmb311Shape)
            {
                int dialectBytesLength = Dialects.Length * sizeof(ushort);
                int negotiateContextOffset = 0;

                if (NegotiateContextCount != 0 || NegotiateContextData.Length != 0)
                {
                    negotiateContextOffset = ProtocolConstants.Smb2HeaderLength + AlignToEight(FixedHeaderLength + dialectBytesLength);
                }

                writer.WriteUInt32((uint)negotiateContextOffset);
                writer.WriteUInt16(NegotiateContextCount);
                writer.WriteUInt16(0);
            }
            else
            {
                writer.WriteUInt64(ClientStartTime);
            }

            for (int index = 0; index < Dialects.Length; index++)
            {
                writer.WriteUInt16(SmbDialectCatalog.ToSmb2WireDialect(Dialects[index]));
            }

            if (carriesSmb311Shape && NegotiateContextData.Length != 0)
            {
                int paddingLength = AlignToEight(writer.Length) - writer.Length;

                for (int index = 0; index < paddingLength; index++)
                {
                    writer.WriteByte(0);
                }

                writer.WriteBytes(NegotiateContextData);
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2NegotiateRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 negotiate request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate request structure size must be 36 bytes.");
            }

            ushort dialectCount = reader.ReadUInt16();
            Smb2NegotiateRequest request = new Smb2NegotiateRequest
            {
                SecurityMode = (Smb2SecurityMode)reader.ReadUInt16()
            };

            reader.Skip(2);
            request.Capabilities = (Smb2GlobalCapabilities)reader.ReadUInt32();
            request.ClientGuid = new Guid(reader.ReadBytes(16));
            byte[] trailingHeaderBytes = reader.ReadBytes(8);

            if (dialectCount == 0)
            {
                throw new ProtocolEncodingException("The SMB2 negotiate request must advertise at least one dialect.");
            }

            SmbDialect[] dialects = new SmbDialect[dialectCount];

            for (int index = 0; index < dialectCount; index++)
            {
                ushort wireDialect = reader.ReadUInt16();

                if (!SmbDialectCatalog.TryFromSmb2WireDialect(wireDialect, out SmbDialect dialect))
                {
                    throw new ProtocolEncodingException("The SMB2 negotiate request contains an unknown dialect value.");
                }

                dialects[index] = dialect;
            }

            request.Dialects = dialects;

            if (Array.IndexOf(dialects, SmbDialect.Smb311) >= 0)
            {
                LittleEndianReader trailingHeaderReader = new LittleEndianReader(trailingHeaderBytes);
                request.NegotiateContextOffset = trailingHeaderReader.ReadUInt32();
                request.NegotiateContextCount = trailingHeaderReader.ReadUInt16();
                trailingHeaderReader.Skip(2);

                if (request.NegotiateContextCount != 0)
                {
                    int minimumRelativeOffset = AlignToEight(FixedHeaderLength + (dialectCount * sizeof(ushort)));

                    if (request.NegotiateContextOffset > Int32.MaxValue)
                    {
                        throw new ProtocolEncodingException("The SMB 3.1.1-style negotiate context offset is malformed.");
                    }

                    int relativeNegotiateContextOffset = checked((int)request.NegotiateContextOffset - ProtocolConstants.Smb2HeaderLength);

                    if (relativeNegotiateContextOffset < minimumRelativeOffset ||
                        relativeNegotiateContextOffset >= buffer.Length)
                    {
                        throw new ProtocolEncodingException("The SMB 3.1.1-style negotiate context offset is malformed.");
                    }

                    request.NegotiateContextData = buffer.Slice(relativeNegotiateContextOffset).ToArray();
                }
            }
            else
            {
                request.ClientStartTime = BinaryPrimitives.ReadUInt64LittleEndian(trailingHeaderBytes);
            }

            return request;
        }

        private SmbDialect[] _Dialects = new SmbDialect[] { SmbDialect.Smb2002 };
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
