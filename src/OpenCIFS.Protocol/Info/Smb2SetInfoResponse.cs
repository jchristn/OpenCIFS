namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 set-info response payload.
    /// </summary>
    public sealed class Smb2SetInfoResponse
    {
        private const ushort StructureSize = 2;

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2SetInfoResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 set-info response must be exactly 2 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 set-info response structure size must be 2 bytes.");
            }

            return new Smb2SetInfoResponse();
        }
    }
}
