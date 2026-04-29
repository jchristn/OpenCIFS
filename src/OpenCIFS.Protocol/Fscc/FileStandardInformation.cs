namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_STANDARD_INFORMATION payload.
    /// </summary>
    public sealed class FileStandardInformation
    {
        private const int StructureLength = 24;

        /// <summary>
        /// Allocation size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// End-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// Link count.
        /// </summary>
        public uint NumberOfLinks { get; set; }

        /// <summary>
        /// Whether deletion has been requested.
        /// </summary>
        public bool DeletePending { get; set; }

        /// <summary>
        /// Whether the open references a directory.
        /// </summary>
        public bool Directory { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(AllocationSize);
            writer.WriteUInt64(EndOfFile);
            writer.WriteUInt32(NumberOfLinks);
            writer.WriteByte(DeletePending ? (byte)1 : (byte)0);
            writer.WriteByte(Directory ? (byte)1 : (byte)0);
            writer.WriteUInt16(0);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileStandardInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_STANDARD_INFORMATION must be exactly 24 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            byte deletePending;
            byte directory;
            FileStandardInformation information = new FileStandardInformation
            {
                AllocationSize = reader.ReadUInt64(),
                EndOfFile = reader.ReadUInt64(),
                NumberOfLinks = reader.ReadUInt32(),
                DeletePending = (deletePending = reader.ReadByte()) != 0,
                Directory = (directory = reader.ReadByte()) != 0
            };

            if (deletePending > 1 || directory > 1)
            {
                throw new ProtocolEncodingException("FILE_STANDARD_INFORMATION contains an invalid Boolean field.");
            }

            reader.Skip(2);
            return information;
        }
    }
}
