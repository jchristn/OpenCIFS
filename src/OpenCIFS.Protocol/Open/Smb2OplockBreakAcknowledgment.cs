namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 oplock-break acknowledgment payload sent by the client.
    /// </summary>
    public sealed class Smb2OplockBreakAcknowledgment
    {
        private const ushort StructureSize = 24;

        /// <summary>
        /// Lowered oplock level accepted by the client.
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
        /// Serialize the acknowledgment payload to wire format.
        /// </summary>
        /// <returns>Acknowledgment bytes.</returns>
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
        /// Parse the acknowledgment payload from wire format.
        /// </summary>
        /// <param name="buffer">Acknowledgment bytes.</param>
        /// <returns>Parsed acknowledgment.</returns>
        public static Smb2OplockBreakAcknowledgment ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 oplock-break acknowledgment.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 oplock-break acknowledgment structure size must be 24 bytes.");
            }

            Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
            {
                OplockLevel = (Smb2OplockLevel)reader.ReadByte()
            };
            reader.Skip(1);
            reader.Skip(4);
            acknowledgment.PersistentFileId = reader.ReadUInt64();
            acknowledgment.VolatileFileId = reader.ReadUInt64();
            return acknowledgment;
        }
    }
}
