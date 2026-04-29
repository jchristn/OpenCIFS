namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_ALL_INFORMATION payload.
    /// </summary>
    public sealed class FileAllInformation
    {
        private const int FixedBodyLength = 96;
        private const int MinimumLength = 100;

        /// <summary>
        /// Basic information.
        /// </summary>
        public FileBasicInformation BasicInformation { get; set; } = new FileBasicInformation();

        /// <summary>
        /// Standard information.
        /// </summary>
        public FileStandardInformation StandardInformation { get; set; } = new FileStandardInformation();

        /// <summary>
        /// Internal file identifier.
        /// </summary>
        public ulong InternalIndexNumber { get; set; }

        /// <summary>
        /// Extended attribute size.
        /// </summary>
        public uint EaSize { get; set; }

        /// <summary>
        /// Granted access mask.
        /// </summary>
        public uint AccessFlags { get; set; }

        /// <summary>
        /// Current byte offset.
        /// </summary>
        public ulong CurrentByteOffset { get; set; }

        /// <summary>
        /// Mode flags.
        /// </summary>
        public uint Mode { get; set; }

        /// <summary>
        /// Alignment requirement.
        /// </summary>
        public uint AlignmentRequirement { get; set; }

        /// <summary>
        /// Name information.
        /// </summary>
        public FileNameInformation NameInformation { get; set; } = new FileNameInformation();

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(BasicInformation.ToByteArray());
            writer.WriteBytes(StandardInformation.ToByteArray());
            writer.WriteUInt64(InternalIndexNumber);
            writer.WriteUInt32(EaSize);
            writer.WriteUInt32(AccessFlags);
            writer.WriteUInt64(CurrentByteOffset);
            writer.WriteUInt32(Mode);
            writer.WriteUInt32(AlignmentRequirement);
            writer.WriteBytes(NameInformation.ToByteArray());
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileAllInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < MinimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete FILE_ALL_INFORMATION structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(64, 32));
            FileNameInformation nameInformation = FileNameInformation.ReadFrom(buffer.Slice(FixedBodyLength));
            FileAllInformation information = new FileAllInformation
            {
                BasicInformation = FileBasicInformation.ReadFrom(buffer.Slice(0, 40)),
                StandardInformation = FileStandardInformation.ReadFrom(buffer.Slice(40, 24)),
                InternalIndexNumber = reader.ReadUInt64(),
                EaSize = reader.ReadUInt32(),
                AccessFlags = reader.ReadUInt32(),
                CurrentByteOffset = reader.ReadUInt64(),
                Mode = reader.ReadUInt32(),
                AlignmentRequirement = reader.ReadUInt32(),
                NameInformation = nameInformation
            };

            if (FixedBodyLength + nameInformation.ToByteArray().Length != buffer.Length)
            {
                throw new ProtocolEncodingException("The FILE_ALL_INFORMATION name payload length does not match the available buffer.");
            }

            return information;
        }
    }
}
