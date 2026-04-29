namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FSCC file attributes.
    /// </summary>
    [Flags]
    public enum FileAttributes : uint
    {
        /// <summary>
        /// No attributes.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Read-only file.
        /// </summary>
        ReadOnly = 0x00000001,

        /// <summary>
        /// Hidden file.
        /// </summary>
        Hidden = 0x00000002,

        /// <summary>
        /// System file.
        /// </summary>
        System = 0x00000004,

        /// <summary>
        /// Directory.
        /// </summary>
        Directory = 0x00000010,

        /// <summary>
        /// Archive file.
        /// </summary>
        Archive = 0x00000020,

        /// <summary>
        /// Normal file.
        /// </summary>
        Normal = 0x00000080,

        /// <summary>
        /// Temporary file.
        /// </summary>
        Temporary = 0x00000100,

        /// <summary>
        /// Sparse file.
        /// </summary>
        SparseFile = 0x00000200,

        /// <summary>
        /// Reparse point.
        /// </summary>
        ReparsePoint = 0x00000400,

        /// <summary>
        /// Compressed file.
        /// </summary>
        Compressed = 0x00000800,

        /// <summary>
        /// Offline file.
        /// </summary>
        Offline = 0x00001000,

        /// <summary>
        /// Not content indexed.
        /// </summary>
        NotContentIndexed = 0x00002000,

        /// <summary>
        /// Encrypted file.
        /// </summary>
        Encrypted = 0x00004000
    }
}

