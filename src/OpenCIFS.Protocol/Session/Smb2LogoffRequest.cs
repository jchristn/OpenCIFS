namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 logoff request payload.
    /// </summary>
    public sealed class Smb2LogoffRequest
    {
        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(4);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2LogoffRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != 4)
            {
                throw new ProtocolEncodingException("The SMB2 logoff request must be exactly 4 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != 4)
            {
                throw new ProtocolEncodingException("The SMB2 logoff request structure size must be 4 bytes.");
            }

            reader.Skip(2);
            return new Smb2LogoffRequest();
        }
    }
}
