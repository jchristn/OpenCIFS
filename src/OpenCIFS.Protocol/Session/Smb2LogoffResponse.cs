namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 logoff response payload.
    /// </summary>
    public sealed class Smb2LogoffResponse
    {
        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(4);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2LogoffResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != 4)
            {
                throw new ProtocolEncodingException("The SMB2 logoff response must be exactly 4 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != 4)
            {
                throw new ProtocolEncodingException("The SMB2 logoff response structure size must be 4 bytes.");
            }

            reader.Skip(2);
            return new Smb2LogoffResponse();
        }
    }
}
