namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 write response payload.
    /// </summary>
    public sealed class Smb2WriteResponse
    {
        private const ushort StructureSize = 17;

        /// <summary>
        /// Bytes written.
        /// </summary>
        public uint Count { get; set; }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(0);
            writer.WriteUInt32(Count);
            writer.WriteUInt32(0);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2WriteResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != 16)
            {
                throw new ProtocolEncodingException("The SMB2 write response must be exactly 16 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 write response structure size must be 17 bytes.");
            }

            reader.Skip(2);
            Smb2WriteResponse response = new Smb2WriteResponse
            {
                Count = reader.ReadUInt32()
            };

            reader.Skip(4);
            reader.Skip(2);
            reader.Skip(2);
            return response;
        }
    }
}
