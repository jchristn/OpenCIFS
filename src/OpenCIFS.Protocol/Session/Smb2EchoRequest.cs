namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 echo request payload.
    /// </summary>
    public sealed class Smb2EchoRequest
    {
        private const ushort StructureSize = 4;

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2EchoRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 echo request must be exactly 4 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 echo request structure size must be 4 bytes.");
            }

            reader.Skip(2);
            return new Smb2EchoRequest();
        }
    }
}
