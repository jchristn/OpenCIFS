namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 oplock-break response payload returned by the server after an acknowledgment.
    /// </summary>
    public sealed class Smb2OplockBreakResponse
    {
        private const ushort StructureSize = 24;

        /// <summary>
        /// Final oplock level granted by the server.
        /// </summary>
        public Smb2OplockLevel OplockLevel { get; set; } = Smb2OplockLevel.None;

        /// <summary>
        /// Persistent file identifier for the affected open.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier for the affected open.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Serialize the response payload to wire format.
        /// </summary>
        /// <returns>Response bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteByte((byte)OplockLevel);
            writer.WriteByte(0);
            writer.WriteUInt32(0);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response payload from wire format.
        /// </summary>
        /// <param name="buffer">Response bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2OplockBreakResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 oplock-break response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 oplock-break response structure size must be 24 bytes.");
            }

            Smb2OplockBreakResponse response = new Smb2OplockBreakResponse
            {
                OplockLevel = (Smb2OplockLevel)reader.ReadByte()
            };
            reader.Skip(1);
            reader.Skip(4);
            response.PersistentFileId = reader.ReadUInt64();
            response.VolatileFileId = reader.ReadUInt64();
            return response;
        }
    }
}
