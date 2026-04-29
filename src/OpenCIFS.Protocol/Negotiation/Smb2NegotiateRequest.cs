namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 negotiate request payload.
    /// </summary>
    public sealed class Smb2NegotiateRequest
    {
        private const ushort StructureSize = 36;

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
            writer.WriteUInt64(ClientStartTime);

            for (int index = 0; index < Dialects.Length; index++)
            {
                writer.WriteUInt16(SmbDialectCatalog.ToSmb2WireDialect(Dialects[index]));
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
            request.ClientStartTime = reader.ReadUInt64();

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
            return request;
        }

        private SmbDialect[] _Dialects = new SmbDialect[] { SmbDialect.Smb2002 };
    }
}
