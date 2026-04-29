namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// CHANGE_NOTIFY completion-filter bits.
    /// </summary>
    [Flags]
    public enum FileNotifyChangeFilter : uint
    {
        /// <summary>
        /// No filter bits.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// File-name changes.
        /// </summary>
        FileName = 0x00000001,

        /// <summary>
        /// Directory-name changes.
        /// </summary>
        DirName = 0x00000002,

        /// <summary>
        /// Attribute changes.
        /// </summary>
        Attributes = 0x00000004,

        /// <summary>
        /// Size changes.
        /// </summary>
        Size = 0x00000008,

        /// <summary>
        /// Last-write time changes.
        /// </summary>
        LastWrite = 0x00000010,

        /// <summary>
        /// Last-access time changes.
        /// </summary>
        LastAccess = 0x00000020,

        /// <summary>
        /// Creation-time changes.
        /// </summary>
        Creation = 0x00000040
    }
}
