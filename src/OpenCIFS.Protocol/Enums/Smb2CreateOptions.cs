namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 create options used by the current file-I/O slice.
    /// </summary>
    [Flags]
    public enum Smb2CreateOptions : uint
    {
        /// <summary>
        /// No create options.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Open a directory.
        /// </summary>
        DirectoryFile = 0x00000001,

        /// <summary>
        /// Write-through.
        /// </summary>
        WriteThrough = 0x00000002,

        /// <summary>
        /// Sequential-only access hint.
        /// </summary>
        SequentialOnly = 0x00000004,

        /// <summary>
        /// Non-directory file.
        /// </summary>
        NonDirectoryFile = 0x00000040,

        /// <summary>
        /// Delete on close.
        /// </summary>
        DeleteOnClose = 0x00001000,

        /// <summary>
        /// Open reparse point.
        /// </summary>
        OpenReparsePoint = 0x00200000
    }
}
