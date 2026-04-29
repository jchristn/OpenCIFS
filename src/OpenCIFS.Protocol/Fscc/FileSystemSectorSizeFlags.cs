namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FILE_FS_SECTOR_SIZE_INFORMATION flags.
    /// </summary>
    [System.Flags]
    public enum FileSystemSectorSizeFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,

        /// <summary>
        /// The first physical sector is aligned with the first logical sector.
        /// </summary>
        AlignedDevice = 0x00000001,

        /// <summary>
        /// The partition is aligned on device-sector boundaries.
        /// </summary>
        PartitionAlignedOnDevice = 0x00000002,

        /// <summary>
        /// The device has no seek penalty.
        /// </summary>
        NoSeekPenalty = 0x00000004,

        /// <summary>
        /// TRIM is enabled.
        /// </summary>
        TrimEnabled = 0x00000008
    }
}
