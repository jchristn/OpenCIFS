namespace OpenCIFS.Protocol
{
    /// <summary>
    /// FSCC file information classes used by query and set info paths.
    /// </summary>
    public enum FileInformationClass : byte
    {
        /// <summary>
        /// Directory information.
        /// </summary>
        DirectoryInformation = 0x01,

        /// <summary>
        /// Full directory information.
        /// </summary>
        FullDirectoryInformation = 0x02,

        /// <summary>
        /// Both directory information.
        /// </summary>
        BothDirectoryInformation = 0x03,

        /// <summary>
        /// Basic information.
        /// </summary>
        BasicInformation = 0x04,

        /// <summary>
        /// Standard information.
        /// </summary>
        StandardInformation = 0x05,

        /// <summary>
        /// Internal information.
        /// </summary>
        InternalInformation = 0x06,

        /// <summary>
        /// Extended attribute information.
        /// </summary>
        EaInformation = 0x07,

        /// <summary>
        /// Access information.
        /// </summary>
        AccessInformation = 0x08,

        /// <summary>
        /// Name information.
        /// </summary>
        NameInformation = 0x09,

        /// <summary>
        /// Rename information.
        /// </summary>
        RenameInformation = 0x0A,

        /// <summary>
        /// Disposition information.
        /// </summary>
        DispositionInformation = 0x0D,

        /// <summary>
        /// Allocation information.
        /// </summary>
        AllocationInformation = 0x13,

        /// <summary>
        /// End-of-file information.
        /// </summary>
        EndOfFileInformation = 0x14,

        /// <summary>
        /// All information.
        /// </summary>
        AllInformation = 0x12,

        /// <summary>
        /// Stream information.
        /// </summary>
        StreamInformation = 0x16,

        /// <summary>
        /// Network open information.
        /// </summary>
        NetworkOpenInformation = 0x22,

        /// <summary>
        /// ID both directory information.
        /// </summary>
        IdBothDirectoryInformation = 0x25,

        /// <summary>
        /// ID full directory information.
        /// </summary>
        IdFullDirectoryInformation = 0x26,

        /// <summary>
        /// Normalized name information.
        /// </summary>
        NormalizedNameInformation = 0x30
    }
}
