namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// VALIDATE_NEGOTIATE_INFO response payload returned from FSCTL_VALIDATE_NEGOTIATE_INFO.
    /// </summary>
    public sealed class ValidateNegotiateInfoResponse
    {
        private const int FixedBodyLength = 24;

        /// <summary>
        /// Server capabilities from the negotiated connection.
        /// </summary>
        public Smb2GlobalCapabilities Capabilities { get; set; } = Smb2GlobalCapabilities.None;

        /// <summary>
        /// Server GUID from the negotiated connection.
        /// </summary>
        public Guid ServerGuid { get; set; } = Guid.Empty;

        /// <summary>
        /// Server security mode from the negotiated connection.
        /// </summary>
        public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        /// <summary>
        /// Negotiated dialect for the connection.
        /// </summary>
        public SmbDialect Dialect { get; set; } = SmbDialect.Smb2002;

        /// <summary>
        /// Serialize the response to wire format.
        /// </summary>
        /// <returns>Serialized bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteBytes(ServerGuid.ToByteArray());
            writer.WriteUInt16((ushort)SecurityMode);
            writer.WriteUInt16(SmbDialectCatalog.ToSmb2WireDialect(Dialect));
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response from wire format.
        /// </summary>
        /// <param name="buffer">Wire-format bytes.</param>
        /// <returns>Parsed response.</returns>
        public static ValidateNegotiateInfoResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != FixedBodyLength)
            {
                throw new ProtocolEncodingException("The VALIDATE_NEGOTIATE_INFO response must be exactly 24 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ValidateNegotiateInfoResponse response = new ValidateNegotiateInfoResponse
            {
                Capabilities = (Smb2GlobalCapabilities)reader.ReadUInt32(),
                ServerGuid = new Guid(reader.ReadBytes(16)),
                SecurityMode = (Smb2SecurityMode)reader.ReadUInt16()
            };
            ushort wireDialect = reader.ReadUInt16();

            if (!SmbDialectCatalog.TryFromSmb2WireDialect(wireDialect, out SmbDialect dialect))
            {
                throw new ProtocolEncodingException("The VALIDATE_NEGOTIATE_INFO response contains an unknown dialect value.");
            }

            response.Dialect = dialect;
            return response;
        }
    }
}
