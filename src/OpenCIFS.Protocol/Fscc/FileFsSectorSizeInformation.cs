namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_FS_SECTOR_SIZE_INFORMATION payload.
    /// </summary>
    public sealed class FileFsSectorSizeInformation
    {
        private const int StructureLength = 28;

        /// <summary>
        /// Logical bytes per sector.
        /// </summary>
        public uint LogicalBytesPerSector { get; set; }

        /// <summary>
        /// Physical bytes per sector used for atomicity.
        /// </summary>
        public uint PhysicalBytesPerSectorForAtomicity { get; set; }

        /// <summary>
        /// Physical bytes per sector used for performance guidance.
        /// </summary>
        public uint PhysicalBytesPerSectorForPerformance { get; set; }

        /// <summary>
        /// Effective filesystem bytes per sector used for atomicity.
        /// </summary>
        public uint FileSystemEffectivePhysicalBytesPerSectorForAtomicity { get; set; }

        /// <summary>
        /// Sector-size flags.
        /// </summary>
        public FileSystemSectorSizeFlags Flags { get; set; } = FileSystemSectorSizeFlags.None;

        /// <summary>
        /// Byte offset for sector alignment.
        /// </summary>
        public uint ByteOffsetForSectorAlignment { get; set; }

        /// <summary>
        /// Byte offset for partition alignment.
        /// </summary>
        public uint ByteOffsetForPartitionAlignment { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(LogicalBytesPerSector);
            writer.WriteUInt32(PhysicalBytesPerSectorForAtomicity);
            writer.WriteUInt32(PhysicalBytesPerSectorForPerformance);
            writer.WriteUInt32(FileSystemEffectivePhysicalBytesPerSectorForAtomicity);
            writer.WriteUInt32((uint)Flags);
            writer.WriteUInt32(ByteOffsetForSectorAlignment);
            writer.WriteUInt32(ByteOffsetForPartitionAlignment);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileFsSectorSizeInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_FS_SECTOR_SIZE_INFORMATION must be exactly 28 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileFsSectorSizeInformation
            {
                LogicalBytesPerSector = reader.ReadUInt32(),
                PhysicalBytesPerSectorForAtomicity = reader.ReadUInt32(),
                PhysicalBytesPerSectorForPerformance = reader.ReadUInt32(),
                FileSystemEffectivePhysicalBytesPerSectorForAtomicity = reader.ReadUInt32(),
                Flags = (FileSystemSectorSizeFlags)reader.ReadUInt32(),
                ByteOffsetForSectorAlignment = reader.ReadUInt32(),
                ByteOffsetForPartitionAlignment = reader.ReadUInt32()
            };
        }
    }
}
