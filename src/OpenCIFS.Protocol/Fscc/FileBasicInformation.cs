namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_BASIC_INFORMATION payload.
    /// </summary>
    public sealed class FileBasicInformation
    {
        private const int StructureLength = 40;

        /// <summary>
        /// Creation time in FILETIME form.
        /// </summary>
        public ulong CreationTime { get; set; }

        /// <summary>
        /// Last-access time in FILETIME form.
        /// </summary>
        public ulong LastAccessTime { get; set; }

        /// <summary>
        /// Last-write time in FILETIME form.
        /// </summary>
        public ulong LastWriteTime { get; set; }

        /// <summary>
        /// Change time in FILETIME form.
        /// </summary>
        public ulong ChangeTime { get; set; }

        /// <summary>
        /// File attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.None;

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(CreationTime);
            writer.WriteUInt64(LastAccessTime);
            writer.WriteUInt64(LastWriteTime);
            writer.WriteUInt64(ChangeTime);
            writer.WriteUInt32((uint)FileAttributes);
            writer.WriteUInt32(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileBasicInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_BASIC_INFORMATION must be exactly 40 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            FileBasicInformation information = new FileBasicInformation
            {
                CreationTime = reader.ReadUInt64(),
                LastAccessTime = reader.ReadUInt64(),
                LastWriteTime = reader.ReadUInt64(),
                ChangeTime = reader.ReadUInt64(),
                FileAttributes = (FileAttributes)reader.ReadUInt32()
            };
            reader.Skip(4);
            return information;
        }
    }
}
