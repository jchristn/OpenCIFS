namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 session-setup request payload.
    /// </summary>
    public sealed class Smb2SessionSetupRequest
    {
        private const ushort StructureSize = 25;
        private const ushort FixedBodyLength = 24;

        /// <summary>
        /// Session-setup flags.
        /// </summary>
        public byte Flags { get; set; }

        /// <summary>
        /// Requested session security mode.
        /// </summary>
        public Smb2SecurityMode SecurityMode { get; set; } = Smb2SecurityMode.SigningEnabled;

        /// <summary>
        /// Client capabilities.
        /// </summary>
        public Smb2GlobalCapabilities Capabilities { get; set; } = Smb2GlobalCapabilities.None;

        /// <summary>
        /// Channel identifier. Always zero for the current implementation.
        /// </summary>
        public uint Channel { get; set; }

        /// <summary>
        /// Previous session identifier for reconnect scenarios.
        /// </summary>
        public ulong PreviousSessionId { get; set; }

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
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            ushort securityBufferOffset = SecurityBuffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            writer.WriteUInt16(StructureSize);
            writer.WriteByte(Flags);
            writer.WriteByte((byte)SecurityMode);
            writer.WriteUInt32((uint)Capabilities);
            writer.WriteUInt32(Channel);
            writer.WriteUInt16(securityBufferOffset);
            writer.WriteUInt16((ushort)SecurityBuffer.Length);
            writer.WriteUInt64(PreviousSessionId);
            writer.WriteBytes(SecurityBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2SessionSetupRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 session-setup request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup request structure size must be 25 bytes.");
            }

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                Flags = reader.ReadByte(),
                SecurityMode = (Smb2SecurityMode)reader.ReadByte(),
                Capabilities = (Smb2GlobalCapabilities)reader.ReadUInt32(),
                Channel = reader.ReadUInt32()
            };

            ushort securityBufferOffset = reader.ReadUInt16();
            ushort securityBufferLength = reader.ReadUInt16();
            request.PreviousSessionId = reader.ReadUInt64();

            if (securityBufferLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 session-setup request contains trailing bytes without a security buffer length.");
                }

                request.SecurityBuffer = Array.Empty<byte>();
                return request;
            }

            int relativeSecurityBufferOffset = securityBufferOffset - ProtocolConstants.Smb2HeaderLength;

            if (relativeSecurityBufferOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup request security-buffer offset is invalid.");
            }

            if (relativeSecurityBufferOffset + securityBufferLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 session-setup request security buffer exceeds the available payload.");
            }

            request.SecurityBuffer = buffer.Slice(relativeSecurityBufferOffset, securityBufferLength).ToArray();
            return request;
        }

        private byte[] _SecurityBuffer = Array.Empty<byte>();
    }
}
