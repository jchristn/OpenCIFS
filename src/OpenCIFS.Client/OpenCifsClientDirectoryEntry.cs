namespace OpenCIFS.Client
{
    using System;
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

        /// <summary>
        /// Whether the entry is a directory, derived from <see cref="FileAttributes"/>.
        /// </summary>
        public bool IsDirectory
        {
            get
            {
                return (FileAttributes & FileAttributes.Directory) != 0;
            }
        }

        /// <summary>
        /// Creation timestamp in UTC, or null when the server did not report one.
        /// </summary>
        public DateTime? CreationTimeUtc { get; set; }

        /// <summary>
        /// Last-access timestamp in UTC, or null when the server did not report one.
        /// </summary>
        public DateTime? LastAccessTimeUtc { get; set; }

        /// <summary>
        /// Last-write timestamp in UTC, or null when the server did not report one.
        /// </summary>
        public DateTime? LastWriteTimeUtc { get; set; }

        /// <summary>
        /// Change timestamp in UTC, or null when the server did not report one.
        /// </summary>
        public DateTime? ChangeTimeUtc { get; set; }
    }
}
