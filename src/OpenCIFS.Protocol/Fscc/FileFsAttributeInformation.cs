namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// FILE_FS_ATTRIBUTE_INFORMATION payload.
    /// </summary>
    public sealed class FileFsAttributeInformation
    {
        private const int FixedBodyLength = 12;

        /// <summary>
        /// Filesystem attribute flags.
        /// </summary>
        public FileSystemAttributesFlags FileSystemAttributes { get; set; } = FileSystemAttributesFlags.None;

        /// <summary>
        /// Maximum component name length, in characters.
        /// </summary>
        public int MaximumComponentNameLength { get; set; } = 255;

        /// <summary>
        /// Filesystem name.
        /// </summary>
        public string FileSystemName
        {
            get
            {
                return _FileSystemName;
            }
            set
            {
                _FileSystemName = value ?? throw new ArgumentNullException(nameof(FileSystemName), "FileSystemName cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] fileSystemNameBytes = Encoding.Unicode.GetBytes(FileSystemName);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32((uint)FileSystemAttributes);
            writer.WriteUInt32(unchecked((uint)MaximumComponentNameLength));
            writer.WriteUInt32((uint)fileSystemNameBytes.Length);
            writer.WriteBytes(fileSystemNameBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileFsAttributeInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete FILE_FS_ATTRIBUTE_INFORMATION structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            FileSystemAttributesFlags attributes = (FileSystemAttributesFlags)reader.ReadUInt32();
            int maximumComponentNameLength = unchecked((int)reader.ReadUInt32());
            uint fileSystemNameLength = reader.ReadUInt32();

            if ((fileSystemNameLength % 2) != 0)
            {
                throw new ProtocolEncodingException("FILE_FS_ATTRIBUTE_INFORMATION contains an invalid UTF-16 filesystem-name length.");
            }

            if (fileSystemNameLength > Int32.MaxValue || FixedBodyLength + fileSystemNameLength != buffer.Length)
            {
                throw new ProtocolEncodingException("FILE_FS_ATTRIBUTE_INFORMATION length exceeds the available payload.");
            }

            return new FileFsAttributeInformation
            {
                FileSystemAttributes = attributes,
                MaximumComponentNameLength = maximumComponentNameLength,
                FileSystemName = Encoding.Unicode.GetString(buffer.Slice(FixedBodyLength, checked((int)fileSystemNameLength)).ToArray())
            };
        }

        private string _FileSystemName = string.Empty;
    }
}
