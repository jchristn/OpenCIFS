namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_FS_FULL_SIZE_INFORMATION payload.
    /// </summary>
    public sealed class FileFsFullSizeInformation
    {
        private const int StructureLength = 32;

        /// <summary>
        /// Total allocation units.
        /// </summary>
        public ulong TotalAllocationUnits { get; set; }

        /// <summary>
        /// Free allocation units available to the caller.
        /// </summary>
        public ulong CallerAvailableAllocationUnits { get; set; }

        /// <summary>
        /// Total free allocation units on the volume.
        /// </summary>
        public ulong ActualAvailableAllocationUnits { get; set; }

        /// <summary>
        /// Sectors per allocation unit.
        /// </summary>
        public uint SectorsPerAllocationUnit { get; set; }

        /// <summary>
        /// Bytes per sector.
        /// </summary>
        public uint BytesPerSector { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(TotalAllocationUnits);
            writer.WriteUInt64(CallerAvailableAllocationUnits);
            writer.WriteUInt64(ActualAvailableAllocationUnits);
            writer.WriteUInt32(SectorsPerAllocationUnit);
            writer.WriteUInt32(BytesPerSector);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileFsFullSizeInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_FS_FULL_SIZE_INFORMATION must be exactly 32 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileFsFullSizeInformation
            {
                TotalAllocationUnits = reader.ReadUInt64(),
                CallerAvailableAllocationUnits = reader.ReadUInt64(),
                ActualAvailableAllocationUnits = reader.ReadUInt64(),
                SectorsPerAllocationUnit = reader.ReadUInt32(),
                BytesPerSector = reader.ReadUInt32()
            };
        }
    }
}
