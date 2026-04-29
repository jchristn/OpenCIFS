namespace OpenCIFS.Client
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// High-level directory entry returned by the managed client facade.
    /// </summary>
    public sealed class OpenCifsClientDirectoryEntry
    {
        /// <summary>
        /// File or directory name relative to the enumerated path.
        /// </summary>
        public string FileName { get; set; } = string.Empty;

        /// <summary>
        /// Logical end-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// Allocated size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// File attributes reported by the server.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.Normal;
    }
}
