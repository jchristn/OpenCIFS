namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_END_OF_FILE_INFORMATION payload.
    /// </summary>
    public sealed class FileEndOfFileInformation
    {
        private const int StructureLength = 8;

        /// <summary>
        /// Requested end-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(EndOfFile);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileEndOfFileInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_END_OF_FILE_INFORMATION must be exactly 8 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileEndOfFileInformation
            {
                EndOfFile = reader.ReadUInt64()
            };
        }
    }
}
