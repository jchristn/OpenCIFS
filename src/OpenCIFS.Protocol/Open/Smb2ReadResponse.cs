namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 read response payload.
    /// </summary>
    public sealed class Smb2ReadResponse
    {
        private const ushort StructureSize = 17;
        private const ushort FixedBodyLength = 16;

        /// <summary>
        /// Read data buffer.
        /// </summary>
        public byte[] DataBuffer
        {
            get
            {
                return _DataBuffer;
            }
            set
            {
                _DataBuffer = value ?? throw new ArgumentNullException(nameof(DataBuffer), "DataBuffer cannot be null.");
            }
        }

        /// <summary>
        /// Remaining out-of-band data length.
        /// </summary>
        public uint DataRemaining { get; set; }

        /// <summary>
        /// Reserved flags field.
        /// </summary>
        public uint Flags { get; set; }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            byte dataOffset = DataBuffer.Length == 0
                ? (byte)0
                : (byte)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte(dataOffset);
            writer.WriteByte(0);
            writer.WriteUInt32((uint)DataBuffer.Length);
            writer.WriteUInt32(DataRemaining);
            writer.WriteUInt32(Flags);
            writer.WriteBytes(DataBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2ReadResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 read response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 read response structure size must be 17 bytes.");
            }

            byte dataOffset = reader.ReadByte();
            reader.Skip(1);
            uint dataLength = reader.ReadUInt32();
            Smb2ReadResponse response = new Smb2ReadResponse
            {
                DataRemaining = reader.ReadUInt32(),
                Flags = reader.ReadUInt32()
            };

            if (dataLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 read response contains trailing bytes without data.");
                }

                response.DataBuffer = Array.Empty<byte>();
                return response;
            }

            if (dataLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 read response data length exceeds the supported maximum.");
            }

            int relativeDataOffset = dataOffset - ProtocolConstants.Smb2HeaderLength;
            int dataLengthValue = checked((int)dataLength);

            if (relativeDataOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 read response data offset is invalid.");
            }

            if (relativeDataOffset + dataLengthValue > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 read response data buffer exceeds the available payload.");
            }

            response.DataBuffer = buffer.Slice(relativeDataOffset, dataLengthValue).ToArray();
            return response;
        }

        private byte[] _DataBuffer = Array.Empty<byte>();
    }
}
