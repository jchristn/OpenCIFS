namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_FS_DEVICE_INFORMATION payload.
    /// </summary>
    public sealed class FileFsDeviceInformation
    {
        private const int StructureLength = 8;

        /// <summary>
        /// Device type.
        /// </summary>
        public FileSystemDeviceType DeviceType { get; set; } = FileSystemDeviceType.Disk;

        /// <summary>
        /// Device characteristics.
        /// </summary>
        public FileSystemDeviceCharacteristics Characteristics { get; set; } =
            FileSystemDeviceCharacteristics.RemoteDevice |
            FileSystemDeviceCharacteristics.DeviceIsMounted;

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32((uint)DeviceType);
            writer.WriteUInt32((uint)Characteristics);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileFsDeviceInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_FS_DEVICE_INFORMATION must be exactly 8 bytes.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            return new FileFsDeviceInformation
            {
                DeviceType = (FileSystemDeviceType)reader.ReadUInt32(),
                Characteristics = (FileSystemDeviceCharacteristics)reader.ReadUInt32()
            };
        }
    }
}
