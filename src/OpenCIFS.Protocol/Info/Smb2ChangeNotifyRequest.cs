namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 CHANGE_NOTIFY request payload.
    /// </summary>
    public sealed class Smb2ChangeNotifyRequest
    {
        private const ushort StructureSize = 32;
        private const ushort FixedBodyLength = 32;

        /// <summary>
        /// CHANGE_NOTIFY request flags.
        /// </summary>
        public Smb2ChangeNotifyFlags Flags { get; set; } = Smb2ChangeNotifyFlags.None;

        /// <summary>
        /// Maximum response-buffer length.
        /// </summary>
        public uint OutputBufferLength { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Completion-filter bits.
        /// </summary>
        public FileNotifyChangeFilter CompletionFilter { get; set; } = FileNotifyChangeFilter.None;

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)Flags);
            writer.WriteUInt32(OutputBufferLength);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt32((uint)CompletionFilter);
            writer.WriteUInt32(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2ChangeNotifyRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY request must be exactly 32 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY request structure size must be 32 bytes.");
            }

            Smb2ChangeNotifyRequest request = new Smb2ChangeNotifyRequest
            {
                Flags = (Smb2ChangeNotifyFlags)reader.ReadUInt16(),
                OutputBufferLength = reader.ReadUInt32(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64(),
                CompletionFilter = (FileNotifyChangeFilter)reader.ReadUInt32()
            };
            reader.Skip(4);
            return request;
        }
    }
}
