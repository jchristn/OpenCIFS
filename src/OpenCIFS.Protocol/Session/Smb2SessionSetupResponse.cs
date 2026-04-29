namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 session-setup response payload.
    /// </summary>
    public sealed class Smb2SessionSetupResponse
    {
        private const ushort StructureSize = 9;
        private const ushort FixedBodyLength = 8;

        /// <summary>
        /// Session flags.
        /// </summary>
        public Smb2SessionFlags SessionFlags { get; set; } = Smb2SessionFlags.None;

        /// <summary>
        /// Security-buffer bytes.
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
            writer.WriteUInt16((ushort)SessionFlags);
            writer.WriteUInt16(securityBufferOffset);
            writer.WriteUInt16((ushort)SecurityBuffer.Length);
            writer.WriteBytes(SecurityBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2SessionSetupResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 session-setup response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup response structure size must be 9 bytes.");
            }

            Smb2SessionSetupResponse response = new Smb2SessionSetupResponse
            {
                SessionFlags = (Smb2SessionFlags)reader.ReadUInt16()
            };

            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();

            if (securityBufferLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 session-setup response contains trailing bytes without a security buffer length.");
                }

                response.SecurityBuffer = Array.Empty<byte>();
                return response;
            }

            int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativeSecurityBufferOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup response security-buffer offset is invalid.");
            }

            if (relativeSecurityBufferOffset + securityBufferLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup response security buffer exceeds the available payload.");
            }

            response.SecurityBuffer = buffer.Slice(relativeSecurityBufferOffset, securityBufferLength).ToArray();
            return response;
        }

        private byte[] _SecurityBuffer = Array.Empty<byte>();
    }
}
