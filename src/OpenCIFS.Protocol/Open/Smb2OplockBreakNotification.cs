namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 oplock-break notification payload sent by the server.
    /// </summary>
    public sealed class Smb2OplockBreakNotification
    {
        private const ushort StructureSize = 24;

        /// <summary>
        /// New oplock level that the server will accept from the client.
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
        /// Serialize the notification payload to wire format.
        /// </summary>
        /// <returns>Notification bytes.</returns>
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
        /// Parse the notification payload from wire format.
        /// </summary>
        /// <param name="buffer">Notification bytes.</param>
        /// <returns>Parsed notification.</returns>
        public static Smb2OplockBreakNotification ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 oplock-break notification.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 oplock-break notification structure size must be 24 bytes.");
            }

            Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification
            {
                OplockLevel = (Smb2OplockLevel)reader.ReadByte()
            };
            reader.Skip(1);
            reader.Skip(4);
            notification.PersistentFileId = reader.ReadUInt64();
            notification.VolatileFileId = reader.ReadUInt64();
            return notification;
        }
    }
}
