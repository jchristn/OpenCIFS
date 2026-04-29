namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_INTERNAL_INFORMATION payload.
    /// </summary>
    public sealed class FileInternalInformation
    {
        private const int StructureLength = 8;

        /// <summary>
        /// Stable index number for the file.
        /// </summary>
        public ulong IndexNumber { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(IndexNumber);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileInternalInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_INTERNAL_INFORMATION must be exactly 8 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileInternalInformation
            {
                IndexNumber = reader.ReadUInt64()
            };
        }
    }
}
