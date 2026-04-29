namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// FILE_FS_VOLUME_INFORMATION payload.
    /// </summary>
    public sealed class FileFsVolumeInformation
    {
        private const int FixedBodyLength = 18;

        /// <summary>
        /// Volume creation time in FILETIME form.
        /// </summary>
        public ulong VolumeCreationTime { get; set; }

        /// <summary>
        /// Opaque volume serial number.
        /// </summary>
        public uint VolumeSerialNumber { get; set; }

        /// <summary>
        /// Whether the volume supports object-oriented filesystem objects.
        /// </summary>
        public bool SupportsObjects { get; set; }

        /// <summary>
        /// Volume label.
        /// </summary>
        public string VolumeLabel
        {
            get
            {
                return _VolumeLabel;
            }
            set
            {
                _VolumeLabel = value ?? throw new ArgumentNullException(nameof(VolumeLabel), "VolumeLabel cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] volumeLabelBytes = Encoding.Unicode.GetBytes(VolumeLabel);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(VolumeCreationTime);
            writer.WriteUInt32(VolumeSerialNumber);
            writer.WriteUInt32((uint)volumeLabelBytes.Length);
            writer.WriteByte((byte)(SupportsObjects ? 1 : 0));
            writer.WriteByte(0);
            writer.WriteBytes(volumeLabelBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileFsVolumeInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete FILE_FS_VOLUME_INFORMATION structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ulong volumeCreationTime = reader.ReadUInt64();
            uint volumeSerialNumber = reader.ReadUInt32();
            uint volumeLabelLength = reader.ReadUInt32();
            bool supportsObjects = reader.ReadByte() != 0;
            reader.Skip(1);

            if ((volumeLabelLength % 2) != 0)
            {
                throw new ProtocolEncodingException("FILE_FS_VOLUME_INFORMATION contains an invalid UTF-16 volume-label length.");
            }

            if (volumeLabelLength > Int32.MaxValue || FixedBodyLength + volumeLabelLength != buffer.Length)
            {
                throw new ProtocolEncodingException("FILE_FS_VOLUME_INFORMATION length exceeds the available payload.");
            }

            return new FileFsVolumeInformation
            {
                VolumeCreationTime = volumeCreationTime,
                VolumeSerialNumber = volumeSerialNumber,
                SupportsObjects = supportsObjects,
                VolumeLabel = Encoding.Unicode.GetString(buffer.Slice(FixedBodyLength, checked((int)volumeLabelLength)).ToArray())
            };
        }

        private string _VolumeLabel = string.Empty;
    }
}
