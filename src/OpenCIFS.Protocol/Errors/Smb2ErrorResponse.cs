namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 error-response payload.
    /// </summary>
    public sealed class Smb2ErrorResponse
    {
        private const ushort StructureSize = 9;
        private const int FixedBodyLength = 8;

        /// <summary>
        /// Extended error-data bytes.
        /// </summary>
        public byte[] ErrorData
        {
            get
            {
                return _ErrorData;
            }
            set
            {
                _ErrorData = value ?? throw new ArgumentNullException(nameof(ErrorData), "ErrorData cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the payload to wire format.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte(0);
            writer.WriteByte(0);
            writer.WriteUInt32((uint)ErrorData.Length);
            writer.WriteBytes(ErrorData);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the payload from wire format.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed payload.</returns>
        public static Smb2ErrorResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 error response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 error response structure size must be 9 bytes.");
            }

            byte errorContextCount = reader.ReadByte();

            if (errorContextCount != 0)
            {
                throw new ProtocolEncodingException("The current SMB 2.0.2 slice does not support SMB2 error contexts.");
            }

            reader.Skip(1);
            uint byteCount = reader.ReadUInt32();

            if (byteCount > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 error response data exceeds the supported maximum.");
            }

            int byteCountValue = checked((int)byteCount);

            if (FixedBodyLength + byteCountValue != buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 error response byte count does not match the available payload.");
            }

            return new Smb2ErrorResponse
            {
                ErrorData = buffer.Slice(FixedBodyLength, byteCountValue).ToArray()
            };
        }

        private byte[] _ErrorData = Array.Empty<byte>();
    }
}
