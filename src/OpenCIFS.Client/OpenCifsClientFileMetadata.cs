namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// High-level file or directory metadata returned by the managed client facade.
    /// </summary>
    public sealed class OpenCifsClientFileMetadata
    {
        /// <summary>
        /// Relative path reported by the server for the open.
        /// </summary>
        public string Path { get; set; } = string.Empty;

        /// <summary>
        /// Whether the path references a directory.
        /// </summary>
        public bool IsDirectory { get; set; }

        /// <summary>
        /// Whether the object is marked delete-pending.
        /// </summary>
        public bool IsDeletePending { get; set; }

        /// <summary>
        /// Declared allocation size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// Logical end-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// File attributes reported by the server.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.Normal;

        /// <summary>
        /// Creation time, when available.
        /// </summary>
        public DateTime? CreationTimeUtc { get; set; }

        /// <summary>
        /// Last-access time, when available.
        /// </summary>
        public DateTime? LastAccessTimeUtc { get; set; }

        /// <summary>
        /// Last-write time, when available.
        /// </summary>
        public DateTime? LastWriteTimeUtc { get; set; }

        /// <summary>
        /// Change time, when available.
        /// </summary>
        public DateTime? ChangeTimeUtc { get; set; }
    }
}
