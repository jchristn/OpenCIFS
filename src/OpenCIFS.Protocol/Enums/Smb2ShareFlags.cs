namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 tree-connect share flags.
    /// </summary>
    [Flags]
    public enum Smb2ShareFlags : uint
    {
        /// <summary>
        /// No flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// The share participates in DFS.
        /// </summary>
        Dfs = 0x00000001,

        /// <summary>
        /// The share is a DFS root.
        /// </summary>
        DfsRoot = 0x00000002
    }
}
