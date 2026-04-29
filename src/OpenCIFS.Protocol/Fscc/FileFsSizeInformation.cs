namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_FS_SIZE_INFORMATION payload.
    /// </summary>
    public sealed class FileFsSizeInformation
    {
        private const int FixedBodyLength = 24;

        /// <summary>
        /// Total allocation units on the volume.
        /// </summary>
        public ulong TotalAllocationUnits { get; set; }

        /// <summary>
        /// Available allocation units on the volume.
        /// </summary>
        public ulong AvailableAllocationUnits { get; set; }

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
            writer.WriteUInt64(AvailableAllocationUnits);
            writer.WriteUInt32(SectorsPerAllocationUnit);
            writer.WriteUInt32(BytesPerSector);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileFsSizeInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != FixedBodyLength)
            {
                throw new ProtocolEncodingException("The FILE_FS_SIZE_INFORMATION structure must be exactly 24 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileFsSizeInformation
            {
                TotalAllocationUnits = reader.ReadUInt64(),
                AvailableAllocationUnits = reader.ReadUInt64(),
                SectorsPerAllocationUnit = reader.ReadUInt32(),
                BytesPerSector = reader.ReadUInt32()
            };
        }
    }
}
