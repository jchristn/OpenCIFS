namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lock response payload.
    /// </summary>
    public sealed class Smb2LockResponse
    {
        private const ushort StructureSize = 4;

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Encoded response body.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Encoded response body.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2LockResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 lock response must be exactly 4 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 lock response structure size must be 4 bytes.");
            }

            reader.Skip(2);
            return new Smb2LockResponse();
        }
    }
}
