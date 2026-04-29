namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 close request payload.
    /// </summary>
    public sealed class Smb2CloseRequest
    {
        private const ushort StructureSize = 24;

        /// <summary>
        /// Close flags.
        /// </summary>
        public Smb2CloseFlags Flags { get; set; } = Smb2CloseFlags.None;

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)Flags);
            writer.WriteUInt32(0);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2CloseRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 close request must be exactly 24 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort structureSize = reader.ReadUInt16();

            if (structureSize != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 close request structure size must be 24 bytes.");
            }

            Smb2CloseRequest request = new Smb2CloseRequest
            {
                Flags = (Smb2CloseFlags)reader.ReadUInt16()
            };

            reader.Skip(4);
            request.PersistentFileId = reader.ReadUInt64();
            request.VolatileFileId = reader.ReadUInt64();
            return request;
        }
    }
}
