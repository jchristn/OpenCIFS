namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Flags that control SMB2 query-directory processing.
    /// </summary>
    [Flags]
    public enum Smb2QueryDirectoryFlags : byte
    {
        /// <summary>
        /// No flags are specified.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Restart the directory scan from the beginning.
        /// </summary>
        RestartScans = 0x01,

        /// <summary>
        /// Return only a single matching entry.
        /// </summary>
        ReturnSingleEntry = 0x02,

        /// <summary>
        /// Resume from the supplied file index.
        /// </summary>
        IndexSpecified = 0x04,

        /// <summary>
        /// Restart the scan and change the search pattern.
        /// </summary>
        Reopen = 0x10
    }
}
