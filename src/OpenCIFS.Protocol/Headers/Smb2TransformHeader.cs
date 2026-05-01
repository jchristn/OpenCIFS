namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB 3.x transform header that carries an encrypted SMB2 message.
    /// </summary>
    public sealed class Smb2TransformHeader
    {
        private const int AuthenticatedDataOffset = 20;
        private const ushort ExpectedFlags = 0x0001;

        /// <summary>
        /// Authentication tag produced by the negotiated cipher.
        /// Must be 16 bytes.
        /// </summary>
        public byte[] Signature
        {
            get
            {
                return _Signature;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Signature), "Signature cannot be null.");
                }

                if (value.Length != 16)
                {
                    throw new ArgumentOutOfRangeException(nameof(Signature), "The SMB3 transform signature must be exactly 16 bytes.");
                }

                _Signature = value;
            }
        }

        /// <summary>
        /// Cipher nonce bytes.
        /// Must be 16 bytes.
        /// </summary>
        public byte[] Nonce
        {
            get
            {
                return _Nonce;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Nonce), "Nonce cannot be null.");
                }

                if (value.Length != 16)
                {
                    throw new ArgumentOutOfRangeException(nameof(Nonce), "The SMB3 transform nonce must be exactly 16 bytes.");
                }

                _Nonce = value;
            }
        }

        /// <summary>
        /// Original unencrypted SMB2 message length.
        /// </summary>
        public uint OriginalMessageSize { get; set; }

        /// <summary>
        /// Transform flags.
        /// The bounded SMB 3.0 / 3.0.2 slice currently requires the fixed value <c>0x0001</c>.
        /// </summary>
        public ushort Flags { get; set; } = ExpectedFlags;

        /// <summary>
        /// Session identifier that owns the encrypted message.
        /// </summary>
        public ulong SessionId { get; set; }

        /// <summary>
        /// Serialize the transform header to wire format.
        /// </summary>
        /// <returns>Encoded transform-header bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(ProtocolConstants.Smb2TransformProtocolId);
            writer.WriteBytes(Signature);
            writer.WriteBytes(Nonce);
            writer.WriteUInt32(OriginalMessageSize);
            writer.WriteUInt16(0);
            writer.WriteUInt16(Flags);
            writer.WriteUInt64(SessionId);
            return writer.ToArray();
        }

        /// <summary>
        /// Get the associated-data bytes used by SMB 3.x encryption.
        /// </summary>
        /// <returns>Associated-data bytes.</returns>
        public byte[] GetAuthenticatedData()
        {
            byte[] headerBytes = ToByteArray();
            byte[] authenticatedData = new byte[headerBytes.Length - AuthenticatedDataOffset];
            Buffer.BlockCopy(headerBytes, AuthenticatedDataOffset, authenticatedData, 0, authenticatedData.Length);
            return authenticatedData;
        }

        /// <summary>
        /// Parse the transform header from wire format.
        /// </summary>
        /// <param name="buffer">Wire bytes beginning with an SMB3 transform header.</param>
        /// <returns>Parsed transform header.</returns>
        public static Smb2TransformHeader ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < ProtocolConstants.Smb2TransformHeaderLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB3 transform header.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            byte[] protocolId = reader.ReadBytes(4);

            if (!MatchesProtocol(protocolId, ProtocolConstants.Smb2TransformProtocolId))
            {
                throw new ProtocolEncodingException("The buffer does not contain a valid SMB3 transform protocol identifier.");
            }

            Smb2TransformHeader header = new Smb2TransformHeader
            {
                Signature = reader.ReadBytes(16),
                Nonce = reader.ReadBytes(16),
                OriginalMessageSize = reader.ReadUInt32()
            };

            reader.Skip(2);
            ushort flags = reader.ReadUInt16();

            if (flags != ExpectedFlags)
            {
                throw new ProtocolEncodingException("The SMB3 transform header contains unsupported flags.");
            }

            header.Flags = flags;
            header.SessionId = reader.ReadUInt64();
            return header;
        }

        /// <summary>
        /// Check whether the supplied bytes begin with the SMB3 transform protocol identifier.
        /// </summary>
        /// <param name="buffer">Wire bytes to inspect.</param>
        /// <returns><c>true</c> when the buffer begins with an SMB3 transform header; otherwise <c>false</c>.</returns>
        public static bool LooksLikeTransformHeader(ReadOnlySpan<byte> buffer)
        {
            return buffer.Length >= 4 &&
                buffer[0] == ProtocolConstants.Smb2TransformProtocolId[0] &&
                buffer[1] == ProtocolConstants.Smb2TransformProtocolId[1] &&
                buffer[2] == ProtocolConstants.Smb2TransformProtocolId[2] &&
                buffer[3] == ProtocolConstants.Smb2TransformProtocolId[3];
        }

        private static bool MatchesProtocol(ReadOnlySpan<byte> protocolId, ReadOnlySpan<byte> expectedProtocolId)
        {
            return protocolId.Length == expectedProtocolId.Length &&
                protocolId.SequenceEqual(expectedProtocolId);
        }

        private byte[] _Signature = new byte[16];
        private byte[] _Nonce = new byte[16];
    }
}
