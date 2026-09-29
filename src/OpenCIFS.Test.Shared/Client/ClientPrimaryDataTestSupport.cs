namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;

    /// <summary>
    /// Shared helpers for the primary-surface data-path suites (paging, short reads, ranged and streamed I/O, concurrency).
    /// </summary>
    internal static class ClientPrimaryDataTestSupport
    {
        /// <summary>
        /// Start a live direct-TCP server, connect a primary client, open the default share, and run the supplied body.
        /// </summary>
        /// <param name="prefix">Temporary share directory prefix.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <param name="body">Test body receiving the client, share session, and local share path.</param>
        /// <param name="maximumDialect">Maximum dialect negotiated by the client.</param>
        /// <param name="backendFactory">Optional factory for a custom primary share backend rooted at the local share path.</param>
        /// <returns>Completion task.</returns>
        internal static async Task RunWithPrimaryShareAsync(
            string prefix,
            CancellationToken cancellationToken,
            Func<OpenCifsClient, OpenCifsShareSession, string, Task> body,
            SmbDialect maximumDialect = SmbDialect.Smb21,
            Func<string, OpenCifsServerShareBackend>? backendFactory = null)
        {
            string sharePath = Path.Combine(Path.GetTempPath(), prefix + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sharePath);
            int port = AllocateTcpPort();
            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                sharePath,
                port,
                cancellationToken,
                primaryShareBackend: backendFactory?.Invoke(sharePath)).ConfigureAwait(false);

            try
            {
                await using OpenCifsClient client = new OpenCifsClientBuilder()
                    .WithServer("127.0.0.1", port)
                    .WithDialectRange(SmbDialect.Smb2002, maximumDialect)
                    .Build();
                await client.ConnectAsync(CreateCredential(), cancellationToken).ConfigureAwait(false);
                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, cancellationToken).ConfigureAwait(false);
                await body(client, share, sharePath).ConfigureAwait(false);
            }
            finally
            {
                await StopDirectTcpServerAsync(serverHandle.CancellationTokenSource, serverHandle.ServerTask).ConfigureAwait(false);

                try
                {
                    if (Directory.Exists(sharePath))
                    {
                        Directory.Delete(sharePath, recursive: true);
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }

        /// <summary>
        /// Create a deterministic payload whose bytes vary with position so truncation and misplacement are detectable.
        /// </summary>
        /// <param name="length">Payload length.</param>
        /// <param name="seed">Seed mixed into every byte.</param>
        /// <returns>Payload bytes.</returns>
        internal static byte[] CreatePatternBytes(int length, int seed = 0)
        {
            byte[] bytes = new byte[length];

            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)((index * 31) + (index >> 8) + seed));
            }

            return bytes;
        }

        /// <summary>
        /// Build a long, unique file name used to force directory listings across several QUERY_DIRECTORY pages.
        /// </summary>
        /// <param name="prefix">Name prefix.</param>
        /// <param name="index">Entry index.</param>
        /// <param name="extension">File extension including the leading dot.</param>
        /// <returns>File name.</returns>
        internal static string CreateLongEntryName(string prefix, int index, string extension)
        {
            return prefix + "-" + new string('x', 96) + "-" + index.ToString("D5", System.Globalization.CultureInfo.InvariantCulture) + extension;
        }

        /// <summary>
        /// Read an entire stream into memory.
        /// </summary>
        /// <param name="stream">Source stream.</param>
        /// <param name="bufferSize">Read buffer size.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Stream contents.</returns>
        internal static async Task<byte[]> ReadToEndAsync(Stream stream, int bufferSize, CancellationToken cancellationToken)
        {
            using MemoryStream destination = new MemoryStream();
            byte[] buffer = new byte[bufferSize];

            while (true)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);

                if (read == 0)
                {
                    break;
                }

                destination.Write(buffer, 0, read);
            }

            return destination.ToArray();
        }

        /// <summary>
        /// Collect the set of file names from directory entries.
        /// </summary>
        /// <param name="entries">Directory entries.</param>
        /// <returns>Case-insensitive name set.</returns>
        internal static HashSet<string> GetNames(OpenCifsClientDirectoryEntry[] entries)
        {
            HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int index = 0; index < entries.Length; index++)
            {
                names.Add(entries[index].FileName);
            }

            return names;
        }
    }

    /// <summary>
    /// Filesystem share backend that caps every server-side stream read so the managed server returns legal short SMB2 READ responses.
    /// </summary>
    internal sealed class ShortReadShareBackend : OpenCifsServerShareBackend
    {
        /// <summary>
        /// Initialize the short-read backend.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="rootPath">Local root path.</param>
        /// <param name="maximumReadLength">Maximum bytes returned by any single backing-stream read.</param>
        internal ShortReadShareBackend(string shareName, string rootPath, int maximumReadLength)
        {
            if (maximumReadLength < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(maximumReadLength), "MaximumReadLength must be at least one byte.");
            }

            _Inner = new OpenCifsServerFileSystemShare
            {
                ShareName = shareName,
                RootPath = rootPath,
                CreateRootIfMissing = true
            };
            _MaximumReadLength = maximumReadLength;
        }

        /// <inheritdoc />
        public override string ShareName
        {
            get
            {
                return _Inner.ShareName;
            }
            set
            {
                _Inner.ShareName = value;
            }
        }

        /// <inheritdoc />
        public override string RootPath
        {
            get
            {
                return _Inner.RootPath;
            }
            set
            {
                _Inner.RootPath = value;
            }
        }

        /// <inheritdoc />
        public override bool CreateRootIfMissing
        {
            get
            {
                return _Inner.CreateRootIfMissing;
            }
            set
            {
                _Inner.CreateRootIfMissing = value;
            }
        }

        /// <inheritdoc />
        public override OpenCifsServerShareCapabilities Capabilities
        {
            get
            {
                return _Inner.Capabilities;
            }
        }

        /// <summary>
        /// Number of backing-stream reads that were shortened by this backend.
        /// </summary>
        internal int ShortenedReadCount
        {
            get
            {
                return Volatile.Read(ref _ShortenedReadCount);
            }
        }

        /// <inheritdoc />
        public override void Validate()
        {
            _Inner.Validate();
        }

        /// <inheritdoc />
        public override OpenCifsServerShareBackend Clone()
        {
            return this;
        }

        /// <inheritdoc />
        public override bool DirectoryExists(string fullPath)
        {
            return _Inner.DirectoryExists(fullPath);
        }

        /// <inheritdoc />
        public override bool FileExists(string fullPath)
        {
            return _Inner.FileExists(fullPath);
        }

        /// <inheritdoc />
        public override FileStream OpenFile(string fullPath, FileMode fileMode, FileAccess fileAccess, FileShare fileShare)
        {
            return new ShortReadFileStream(this, fullPath, fileMode, fileAccess, fileShare, _MaximumReadLength);
        }

        /// <inheritdoc />
        public override void SetAttributes(string fullPath, System.IO.FileAttributes attributes)
        {
            _Inner.SetAttributes(fullPath, attributes);
        }

        /// <inheritdoc />
        public override System.IO.FileAttributes GetAttributes(string fullPath)
        {
            return _Inner.GetAttributes(fullPath);
        }

        /// <inheritdoc />
        public override void CreateDirectory(string fullPath)
        {
            _Inner.CreateDirectory(fullPath);
        }

        /// <inheritdoc />
        public override void Move(string sourceFullPath, string destinationFullPath, bool isDirectory)
        {
            _Inner.Move(sourceFullPath, destinationFullPath, isDirectory);
        }

        /// <inheritdoc />
        public override bool DeleteFileIfPresent(string fullPath)
        {
            return _Inner.DeleteFileIfPresent(fullPath);
        }

        /// <inheritdoc />
        public override bool DeleteDirectoryIfPresent(string fullPath, bool recursive)
        {
            return _Inner.DeleteDirectoryIfPresent(fullPath, recursive);
        }

        /// <inheritdoc />
        public override FileSystemInfo GetFileSystemInfo(string fullPath)
        {
            return _Inner.GetFileSystemInfo(fullPath);
        }

        /// <inheritdoc />
        public override IReadOnlyList<FileSystemInfo> EnumerateFileSystemInfos(string fullPath)
        {
            return _Inner.EnumerateFileSystemInfos(fullPath);
        }

        /// <inheritdoc />
        public override void SetCreationTimeUtc(string fullPath, DateTime utcValue, bool isDirectory)
        {
            _Inner.SetCreationTimeUtc(fullPath, utcValue, isDirectory);
        }

        /// <inheritdoc />
        public override void SetLastAccessTimeUtc(string fullPath, DateTime utcValue, bool isDirectory)
        {
            _Inner.SetLastAccessTimeUtc(fullPath, utcValue, isDirectory);
        }

        /// <inheritdoc />
        public override void SetLastWriteTimeUtc(string fullPath, DateTime utcValue, bool isDirectory)
        {
            _Inner.SetLastWriteTimeUtc(fullPath, utcValue, isDirectory);
        }

        internal void RecordShortenedRead()
        {
            Interlocked.Increment(ref _ShortenedReadCount);
        }

        private readonly OpenCifsServerFileSystemShare _Inner;
        private readonly int _MaximumReadLength;
        private int _ShortenedReadCount;
    }

    /// <summary>
    /// File stream that never returns more than a fixed number of bytes per read call.
    /// </summary>
    internal sealed class ShortReadFileStream : FileStream
    {
        /// <summary>
        /// Initialize the short-read file stream.
        /// </summary>
        /// <param name="owner">Owning backend used to record shortened reads.</param>
        /// <param name="path">File path.</param>
        /// <param name="mode">File mode.</param>
        /// <param name="access">File access.</param>
        /// <param name="share">File share mode.</param>
        /// <param name="maximumReadLength">Maximum bytes per read.</param>
        internal ShortReadFileStream(ShortReadShareBackend owner, string path, FileMode mode, FileAccess access, FileShare share, int maximumReadLength)
            : base(path, mode, access, share)
        {
            _Owner = owner;
            _MaximumReadLength = maximumReadLength;
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            return base.Read(buffer, offset, Clamp(count));
        }

        /// <inheritdoc />
        public override int Read(Span<byte> buffer)
        {
            return base.Read(buffer.Slice(0, Clamp(buffer.Length)));
        }

        /// <inheritdoc />
        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        {
            return base.ReadAsync(buffer, offset, Clamp(count), cancellationToken);
        }

        /// <inheritdoc />
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return base.ReadAsync(buffer.Slice(0, Clamp(buffer.Length)), cancellationToken);
        }

        private int Clamp(int count)
        {
            if (count > _MaximumReadLength)
            {
                _Owner.RecordShortenedRead();
                return _MaximumReadLength;
            }

            return count;
        }

        private readonly ShortReadShareBackend _Owner;
        private readonly int _MaximumReadLength;
    }

    /// <summary>
    /// Read-only, non-seekable stream wrapper used to prove streamed uploads do not require seekable sources.
    /// </summary>
    internal sealed class NonSeekableReadStream : Stream
    {
        /// <summary>
        /// Initialize the wrapper.
        /// </summary>
        /// <param name="data">Backing bytes.</param>
        /// <param name="maximumReadLength">Maximum bytes returned per read so callers must loop.</param>
        internal NonSeekableReadStream(byte[] data, int maximumReadLength)
        {
            _Inner = new MemoryStream(data, writable: false);
            _MaximumReadLength = maximumReadLength;
        }

        /// <inheritdoc />
        public override bool CanRead
        {
            get
            {
                return true;
            }
        }

        /// <inheritdoc />
        public override bool CanSeek
        {
            get
            {
                return false;
            }
        }

        /// <inheritdoc />
        public override bool CanWrite
        {
            get
            {
                return false;
            }
        }

        /// <inheritdoc />
        public override long Length
        {
            get
            {
                throw new NotSupportedException("Length is not supported by the non-seekable test stream.");
            }
        }

        /// <inheritdoc />
        public override long Position
        {
            get
            {
                throw new NotSupportedException("Position is not supported by the non-seekable test stream.");
            }
            set
            {
                throw new NotSupportedException("Position is not supported by the non-seekable test stream.");
            }
        }

        /// <inheritdoc />
        public override void Flush()
        {
        }

        /// <inheritdoc />
        public override int Read(byte[] buffer, int offset, int count)
        {
            return _Inner.Read(buffer, offset, Math.Min(count, _MaximumReadLength));
        }

        /// <inheritdoc />
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException("Seek is not supported by the non-seekable test stream.");
        }

        /// <inheritdoc />
        public override void SetLength(long value)
        {
            throw new NotSupportedException("SetLength is not supported by the non-seekable test stream.");
        }

        /// <inheritdoc />
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException("Write is not supported by the non-seekable test stream.");
        }

        /// <inheritdoc />
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _Inner.Dispose();
            }

            base.Dispose(disposing);
        }

        private readonly MemoryStream _Inner;
        private readonly int _MaximumReadLength;
    }
}
