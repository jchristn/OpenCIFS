namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FSCC filesystem information classes used by query info paths.
    /// </summary>
    public enum FileSystemInformationClass : byte
    {
        /// <summary>
        /// Volume information.
        /// </summary>
        VolumeInformation = 0x01,

        /// <summary>
        /// Label information.
        /// </summary>
        LabelInformation = 0x02,

        /// <summary>
        /// Size information.
        /// </summary>
        SizeInformation = 0x03,

        /// <summary>
        /// Device information.
        /// </summary>
        DeviceInformation = 0x04,

        /// <summary>
        /// Attribute information.
        /// </summary>
        AttributeInformation = 0x05,

        /// <summary>
        /// Full size information.
        /// </summary>
        FullSizeInformation = 0x07,

        /// <summary>
        /// Object identifier information.
        /// </summary>
        ObjectIdInformation = 0x08,

        /// <summary>
        /// Sector size information.
        /// </summary>
        SectorSizeInformation = 0x0B
    }
}

