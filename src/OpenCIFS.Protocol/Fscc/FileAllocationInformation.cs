namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_ALLOCATION_INFORMATION payload.
    /// </summary>
    public sealed class FileAllocationInformation
    {
        private const int StructureLength = 8;

        /// <summary>
        /// Requested allocation size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(AllocationSize);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileAllocationInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_ALLOCATION_INFORMATION must be exactly 8 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileAllocationInformation
            {
                AllocationSize = reader.ReadUInt64()
            };
        }
    }
}
