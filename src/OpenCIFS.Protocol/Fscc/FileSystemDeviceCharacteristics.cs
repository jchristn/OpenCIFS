namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FILE_FS_DEVICE_INFORMATION device characteristics.
    /// </summary>
    [System.Flags]
    public enum FileSystemDeviceCharacteristics : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,

        /// <summary>
        /// Removable media.
        /// </summary>
        RemovableMedia = 0x00000001,

        /// <summary>
        /// Read-only device.
        /// </summary>
        ReadOnlyDevice = 0x00000002,

        /// <summary>
        /// Floppy diskette media.
        /// </summary>
        FloppyDiskette = 0x00000004,

        /// <summary>
        /// Write-once media.
        /// </summary>
        WriteOnceMedia = 0x00000008,

        /// <summary>
        /// Remote device.
        /// </summary>
        RemoteDevice = 0x00000010,

        /// <summary>
        /// Mounted device.
        /// </summary>
        DeviceIsMounted = 0x00000020,

        /// <summary>
        /// Virtual volume.
        /// </summary>
        VirtualVolume = 0x00000040,

        /// <summary>
        /// Secure open semantics.
        /// </summary>
        SecureOpen = 0x00000100
    }
}
