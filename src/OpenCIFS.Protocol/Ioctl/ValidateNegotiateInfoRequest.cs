namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// VALIDATE_NEGOTIATE_INFO request payload carried in FSCTL_VALIDATE_NEGOTIATE_INFO.
    /// </summary>
    public sealed class ValidateNegotiateInfoRequest
    {
        private const int FixedBodyLength = 24;

        /// <summary>
        /// Client capabilities from the original negotiate exchange.
        /// </summary>
        public Smb2GlobalCapabilities Capabilities { get; set; } = Smb2GlobalCapabilities.None;

        /// <summary>
        /// Client GUID from the original negotiate exchange.
        /// </summary>
        public Guid ClientGuid { get; set; } = Guid.Empty;

        /// <summary>
        /// Client security mode from the original negotiate exchange.
        /// </summary>
        public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        /// <summary>
        /// Client-offered dialect list from the original negotiate exchange.
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
        /// Serialize the request to wire format.
        /// </summary>
        /// <returns>Serialized bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteBytes(ClientGuid.ToByteArray());
            writer.WriteUInt16((ushort)SecurityMode);
            writer.WriteUInt16((ushort)Dialects.Length);

            for (int index = 0; index < Dialects.Length; index++)
            {
                writer.WriteUInt16(SmbDialectCatalog.ToSmb2WireDialect(Dialects[index]));
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request from wire format.
        /// </summary>
        /// <param name="buffer">Wire-format bytes.</param>
        /// <returns>Parsed request.</returns>
        public static ValidateNegotiateInfoRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete VALIDATE_NEGOTIATE_INFO request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ValidateNegotiateInfoRequest request = new ValidateNegotiateInfoRequest
            {
                Capabilities = (Smb2GlobalCapabilities)reader.ReadUInt32(),
                ClientGuid = new Guid(reader.ReadBytes(16)),
                SecurityMode = (Smb2SecurityMode)reader.ReadUInt16()
            };
            ushort dialectCount = reader.ReadUInt16();

            if (dialectCount == 0)
            {
                throw new ProtocolEncodingException("The VALIDATE_NEGOTIATE_INFO request must include at least one dialect.");
            }

            int expectedLength = checked(FixedBodyLength + (dialectCount * sizeof(ushort)));

            if (buffer.Length != expectedLength)
            {
                throw new ProtocolEncodingException("The VALIDATE_NEGOTIATE_INFO request dialect payload length does not match the available buffer.");
            }

            SmbDialect[] dialects = new SmbDialect[dialectCount];

            for (int index = 0; index < dialects.Length; index++)
            {
                ushort wireDialect = reader.ReadUInt16();

                if (!SmbDialectCatalog.TryFromSmb2WireDialect(wireDialect, out SmbDialect dialect))
                {
                    throw new ProtocolEncodingException("The VALIDATE_NEGOTIATE_INFO request contains an unknown dialect value.");
                }

                dialects[index] = dialect;
            }

            request.Dialects = dialects;
            return request;
        }

        private SmbDialect[] _Dialects = new SmbDialect[] { SmbDialect.Smb2002 };
    }
}
