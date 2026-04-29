namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FILE_NOTIFY_INFORMATION action values.
    /// </summary>
    public enum FileNotifyAction : uint
    {
        /// <summary>
        /// A new entry was added.
        /// </summary>
        Added = 0x00000001,

        /// <summary>
        /// An existing entry was removed.
        /// </summary>
        Removed = 0x00000002,

        /// <summary>
        /// An existing entry was modified.
        /// </summary>
        Modified = 0x00000003,

        /// <summary>
        /// The old name of a same-directory rename.
        /// </summary>
        RenamedOldName = 0x00000004,

        /// <summary>
        /// The new name of a same-directory rename.
        /// </summary>
        RenamedNewName = 0x00000005
    }
}
