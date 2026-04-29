namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FILE_FS_DEVICE_INFORMATION device types.
    /// </summary>
    public enum FileSystemDeviceType : uint
    {
        /// <summary>
        /// CD-ROM device.
        /// </summary>
        CdRom = 0x00000002,

        /// <summary>
        /// Disk device.
        /// </summary>
        Disk = 0x00000007
    }
}
