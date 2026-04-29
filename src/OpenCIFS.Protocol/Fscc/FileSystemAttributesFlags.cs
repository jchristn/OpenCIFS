namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FILE_FS_ATTRIBUTE_INFORMATION attribute flags.
    /// </summary>
    [System.Flags]
    public enum FileSystemAttributesFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0,

        /// <summary>
        /// Case-sensitive search is supported.
        /// </summary>
        CaseSensitiveSearch = 0x00000001,

        /// <summary>
        /// Original filename casing is preserved.
        /// </summary>
        CasePreservedNames = 0x00000002,

        /// <summary>
        /// Unicode names are supported on disk.
        /// </summary>
        UnicodeOnDisk = 0x00000004,

        /// <summary>
        /// Persistent ACLs are supported.
        /// </summary>
        PersistentAcls = 0x00000008,

        /// <summary>
        /// Sparse files are supported.
        /// </summary>
        SupportsSparseFiles = 0x00000040,

        /// <summary>
        /// Reparse points are supported.
        /// </summary>
        SupportsReparsePoints = 0x00000080,

        /// <summary>
        /// Named streams are supported.
        /// </summary>
        NamedStreams = 0x00040000,

        /// <summary>
        /// The volume is read-only.
        /// </summary>
        ReadOnlyVolume = 0x00080000,

        /// <summary>
        /// Hard links are supported.
        /// </summary>
        SupportsHardLinks = 0x00400000,

        /// <summary>
        /// Extended attributes are supported.
        /// </summary>
        SupportsExtendedAttributes = 0x00800000,

        /// <summary>
        /// Open-by-file-id is supported.
        /// </summary>
        SupportsOpenByFileId = 0x01000000
    }
}
