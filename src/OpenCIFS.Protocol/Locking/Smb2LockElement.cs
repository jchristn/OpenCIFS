namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2_LOCK_ELEMENT structure.
    /// </summary>
    public sealed class Smb2LockElement
    {
        internal const int StructureLength = 24;

        /// <summary>
        /// Byte offset where the range starts.
        /// </summary>
        public ulong Offset { get; set; }

        /// <summary>
        /// Byte length of the range.
        /// </summary>
        public ulong Length { get; set; }

        /// <summary>
        /// Lock behavior flags.
        /// </summary>
        public Smb2LockFlags Flags { get; set; } = Smb2LockFlags.None;

        /// <summary>
        /// Serialize the lock element to wire format.
        /// </summary>
        /// <returns>Encoded lock element.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(Offset);
            writer.WriteUInt64(Length);
            writer.WriteUInt32((uint)Flags);
            writer.WriteUInt32(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse a lock element from wire format.
        /// </summary>
        /// <param name="buffer">Encoded lock element.</param>
        /// <returns>Parsed lock element.</returns>
        public static Smb2LockElement ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("The SMB2 lock element must be exactly 24 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            Smb2LockElement element = new Smb2LockElement
            {
                Offset = reader.ReadUInt64(),
                Length = reader.ReadUInt64(),
                Flags = (Smb2LockFlags)reader.ReadUInt32()
            };
            reader.Skip(4);
            return element;
        }
    }
}
