namespace OpenCIFS.SambaInterop.Console
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;
    using SmbFileAttributes = OpenCIFS.Protocol.FileAttributes;

    /// <summary>
    /// Exercises the primary <see cref="OpenCifsClient"/> / <see cref="OpenCifsShareSession"/> surface against Samba:
    /// multi-page enumeration, dot-entry exclusion, directory-entry timestamps, ranged and streamed reads, streamed
    /// writes, existence checks, recursive directory creation, zero-length files, multi-megabyte transfers that exceed
    /// a single transport frame, and concurrent use of one share session.
    /// </summary>
    internal static class SambaInteropPrimarySurfaceRunner
    {
        private const int PagingEntryCount = 1500;
        private const int ConcurrentWorkers = 32;
        private const int MiB = 1024 * 1024;

        internal static async Task<SambaInteropPrimarySurfaceResult> RunAsync(SambaInteropOptions options)
        {
            CancellationToken cancellationToken = CancellationToken.None;
            Stopwatch stopwatch = Stopwatch.StartNew();
            SambaInteropPrimarySurfaceResult result = new SambaInteropPrimarySurfaceResult();
            string root = "opencifs-primary-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            result.Directory = root;

            OpenCifsClientBuilder builder = new OpenCifsClientBuilder()
                .WithServer(options.Server, options.Port)
                .WithDialectRange(options.Dialect, options.Dialect)
                .WithSigningRequired()
                .WithPreferredEncryption(options.Dialect >= SmbDialect.Smb30);

            if (options.Dialect == SmbDialect.Smb311)
            {
                builder = builder.WithSmb311Preview();
            }

            await using OpenCifsClient client = builder.Build();
            await client.ConnectAsync(
                new OpenCifsClientCredential
                {
                    UserName = options.UserName,
                    UserDomain = options.Domain,
                    Password = options.Password
                },
                cancellationToken).ConfigureAwait(false);
            await using OpenCifsShareSession share = await client.OpenShareAsync(options.PrimaryShare, cancellationToken).ConfigureAwait(false);
            result.Share = options.PrimaryShare;

            try
            {
                // Recursive create, idempotence, and the non-recursive failure mode.
                await share.Directories.CreateAsync(root + "/nested/a/b", createParents: true, cancellationToken).ConfigureAwait(false);
                await share.Directories.CreateAsync(root + "/nested/a/b", createParents: true, cancellationToken).ConfigureAwait(false);
                OpenCifsClientResult withoutParents = await share.Directories.TryCreateAsync(root + "/missing/child", createParents: false, cancellationToken).ConfigureAwait(false);
                Require(!withoutParents.IsSuccess, "Expected a non-recursive create beneath a missing parent to fail against Samba.");
                result.CreateParentsVerified = await share.Metadata.ExistsAsync(root + "/nested/a/b", cancellationToken).ConfigureAwait(false);
                Require(result.CreateParentsVerified, "Expected the recursively created directory to exist.");

                // Existence probes.
                await share.Files.WriteAllBytesAsync(root + "/exists.txt", new byte[] { 1, 2, 3 }, cancellationToken).ConfigureAwait(false);
                Require(await share.Metadata.ExistsAsync(root + "/exists.txt", cancellationToken).ConfigureAwait(false), "Expected an existing file to exist.");
                Require(await share.Metadata.ExistsAsync(root, cancellationToken).ConfigureAwait(false), "Expected an existing directory to exist.");
                Require(await share.Metadata.ExistsAsync(string.Empty, cancellationToken).ConfigureAwait(false), "Expected the share root to exist.");
                Require(!await share.Metadata.ExistsAsync(root + "/missing.txt", cancellationToken).ConfigureAwait(false), "Expected a missing file not to exist.");
                Require(!await share.Metadata.ExistsAsync(root + "/missing/child.txt", cancellationToken).ConfigureAwait(false), "Expected a path beneath a missing directory not to exist.");
                Require(!await share.Metadata.ExistsAsync(root + "/exists.txt/child", cancellationToken).ConfigureAwait(false), "Expected a path beneath a file not to exist.");
                result.ExistsVerified = true;

                // Zero-length files through both write paths.
                await share.Files.WriteAllBytesAsync(root + "/empty-bytes.bin", Array.Empty<byte>(), cancellationToken).ConfigureAwait(false);
                Require((await share.Files.ReadAllBytesAsync(root + "/empty-bytes.bin", cancellationToken).ConfigureAwait(false)).Length == 0, "Expected an empty WriteAllBytes file to read back empty.");
                Require((await share.Metadata.GetAttributesAsync(root + "/empty-bytes.bin", cancellationToken).ConfigureAwait(false)).EndOfFile == 0, "Expected an empty WriteAllBytes file to report EOF zero.");
                await share.Files.WriteAllBytesAsync(root + "/shrink.bin", CreatePatternBytes(4096, 1), cancellationToken).ConfigureAwait(false);
                await share.Files.WriteAllBytesAsync(root + "/shrink.bin", Array.Empty<byte>(), cancellationToken).ConfigureAwait(false);
                Require((await share.Metadata.GetAttributesAsync(root + "/shrink.bin", cancellationToken).ConfigureAwait(false)).EndOfFile == 0, "Expected an empty WriteAllBytes to truncate an existing file.");

                using (MemoryStream emptySource = new MemoryStream())
                {
                    await share.Files.WriteAsync(root + "/empty-stream.bin", emptySource, cancellationToken: cancellationToken).ConfigureAwait(false);
                }

                using (MemoryStream zeroLengthSource = new MemoryStream(CreatePatternBytes(100, 2)))
                {
                    await share.Files.WriteAsync(root + "/zero-length.bin", zeroLengthSource, 0, cancellationToken).ConfigureAwait(false);
                }

                Require((await share.Files.ReadAllBytesAsync(root + "/empty-stream.bin", cancellationToken).ConfigureAwait(false)).Length == 0, "Expected an empty-source stream write to create an empty file.");
                Require((await share.Files.ReadAllBytesAsync(root + "/zero-length.bin", cancellationToken).ConfigureAwait(false)).Length == 0, "Expected a zero-length stream write to create an empty file.");
                Require((await share.Files.ReadAsync(root + "/zero-length.bin", 0, 10, cancellationToken).ConfigureAwait(false)).Length == 0, "Expected a ranged read of an empty file to return empty.");
                result.ZeroLengthVerified = true;

                // Read-only files must stay readable through every read path (reads must not request write access).
                byte[] readOnlyContent = CreatePatternBytes(70001, 6);
                await share.Files.WriteAllBytesAsync(root + "/readonly.bin", readOnlyContent, cancellationToken).ConfigureAwait(false);
                await share.Metadata.SetBasicInfoAsync(root + "/readonly.bin", fileAttributes: SmbFileAttributes.ReadOnly, cancellationToken: cancellationToken).ConfigureAwait(false);

                try
                {
                    RequireEqual(readOnlyContent, await share.Files.ReadAllBytesAsync(root + "/readonly.bin", cancellationToken).ConfigureAwait(false), "Expected ReadAllBytes to read a read-only file.");
                    RequireEqual(readOnlyContent.AsSpan(5, 50).ToArray(), await share.Files.ReadAsync(root + "/readonly.bin", 5, 50, cancellationToken).ConfigureAwait(false), "Expected ReadAsync to read a read-only file.");

                    await using (Stream readOnlyStream = await share.Files.OpenReadAsync(root + "/readonly.bin", cancellationToken).ConfigureAwait(false))
                    {
                        RequireEqual(readOnlyContent, await ReadToEndAsync(readOnlyStream, 65536, cancellationToken).ConfigureAwait(false), "Expected OpenReadAsync to read a read-only file.");
                    }

                    OpenCifsClientResult overwrite = await share.Files.TryWriteAllBytesAsync(root + "/readonly.bin", new byte[] { 1 }, cancellationToken).ConfigureAwait(false);
                    Require(!overwrite.IsSuccess, "Expected Samba to reject an overwrite of a read-only file.");
                }
                finally
                {
                    await share.Metadata.SetBasicInfoAsync(root + "/readonly.bin", fileAttributes: SmbFileAttributes.Normal, cancellationToken: cancellationToken).ConfigureAwait(false);
                }

                result.ReadOnlyVerified = true;

                // Multi-megabyte transfers. Samba negotiates 8 MiB READ/WRITE sizes, larger than one transport frame.
                byte[] large = CreatePatternBytes((5 * MiB) + 17, 3);
                await share.Files.WriteAllBytesAsync(root + "/large.bin", large, cancellationToken).ConfigureAwait(false);
                RequireEqual(large, await share.Files.ReadAllBytesAsync(root + "/large.bin", cancellationToken).ConfigureAwait(false), "Expected a multi-megabyte ReadAllBytes round trip.");
                RequireEqual(large.AsSpan(MiB - 7, (2 * MiB) + 14).ToArray(), await share.Files.ReadAsync(root + "/large.bin", (ulong)(MiB - 7), (2 * MiB) + 14, cancellationToken).ConfigureAwait(false), "Expected a multi-chunk ranged read.");
                RequireEqual(large.AsSpan(large.Length - 9).ToArray(), await share.Files.ReadAsync(root + "/large.bin", (ulong)(large.Length - 9), 1000, cancellationToken).ConfigureAwait(false), "Expected a partial ranged read at EOF.");
                Require((await share.Files.ReadAsync(root + "/large.bin", (ulong)large.Length, 10, cancellationToken).ConfigureAwait(false)).Length == 0, "Expected a ranged read at EOF to return empty.");
                OpenCifsClientResult<byte[]> negativeRange = await share.Files.TryReadAsync(root + "/missing.bin", 0, 10, cancellationToken).ConfigureAwait(false);
                Require(!negativeRange.IsSuccess && negativeRange.ErrorCategory == OpenCifsErrorCategory.NotFound, "Expected a ranged read of a missing file to map to NotFound.");
                result.LargeTransferBytes = large.Length;

                // Streamed reads with seeking.
                await using (Stream stream = await share.Files.OpenReadAsync(root + "/large.bin", cancellationToken).ConfigureAwait(false))
                {
                    Require(stream.CanRead && stream.CanSeek && !stream.CanWrite, "Expected a read-only seekable stream.");
                    Require(stream.Length == large.Length, "Expected the stream length to match EOF.");
                    RequireEqual(large, await ReadToEndAsync(stream, 81920, cancellationToken).ConfigureAwait(false), "Expected a streamed read of the full file.");
                    stream.Seek(-5, SeekOrigin.End);
                    byte[] tail = new byte[64];
                    int tailRead = await stream.ReadAsync(tail.AsMemory(), cancellationToken).ConfigureAwait(false);
                    Require(tailRead == 5, "Expected a partial stream read at EOF.");
                    stream.Position = large.Length + 100L;
                    Require(await stream.ReadAsync(tail.AsMemory(), cancellationToken).ConfigureAwait(false) == 0, "Expected a stream read beyond EOF to return zero.");
                    stream.Position = 3 * MiB;
                    int midRead = await stream.ReadAsync(tail.AsMemory(), cancellationToken).ConfigureAwait(false);
                    RequireEqual(large.AsSpan(3 * MiB, midRead).ToArray(), tail.AsSpan(0, midRead).ToArray(), "Expected a seeked stream read to return the bytes at the new position.");
                }

                result.StreamReadVerified = true;

                // Streamed writes from non-seekable sources, exact lengths, overwrite truncation, and short sources.
                byte[] upload = CreatePatternBytes((3 * MiB) + 5, 4);
                using (NonSeekableStream source = new NonSeekableStream(upload, 65521))
                {
                    await share.Files.WriteAsync(root + "/upload.bin", source, cancellationToken: cancellationToken).ConfigureAwait(false);
                }

                RequireEqual(upload, await share.Files.ReadAllBytesAsync(root + "/upload.bin", cancellationToken).ConfigureAwait(false), "Expected a non-seekable streamed upload to round-trip.");

                using (NonSeekableStream source = new NonSeekableStream(upload, 4093))
                {
                    await share.Files.WriteAsync(root + "/upload.bin", source, 70000, cancellationToken).ConfigureAwait(false);
                }

                RequireEqual(upload.AsSpan(0, 70000).ToArray(), await share.Files.ReadAllBytesAsync(root + "/upload.bin", cancellationToken).ConfigureAwait(false), "Expected an exact-length overwrite to truncate the previous content.");
                bool shortSourceRejected = false;

                using (NonSeekableStream source = new NonSeekableStream(CreatePatternBytes(1000, 5), 100))
                {
                    try
                    {
                        await share.Files.WriteAsync(root + "/short.bin", source, 5000, cancellationToken).ConfigureAwait(false);
                    }
                    catch (EndOfStreamException)
                    {
                        shortSourceRejected = true;
                    }
                }

                Require(shortSourceRejected, "Expected a short source with an explicit length to throw EndOfStreamException.");
                await share.Files.DeleteAsync(root + "/short.bin", cancellationToken).ConfigureAwait(false);
                result.StreamWriteVerified = true;

                // Multi-page enumeration created concurrently over the single share session.
                string pagingDirectory = root + "/paging";
                await share.Directories.CreateAsync(pagingDirectory, cancellationToken).ConfigureAwait(false);
                int nextIndex = -1;
                Task[] creators = new Task[16];

                for (int creator = 0; creator < creators.Length; creator++)
                {
                    creators[creator] = Task.Run(async () =>
                    {
                        while (true)
                        {
                            int index = Interlocked.Increment(ref nextIndex);

                            if (index >= PagingEntryCount)
                            {
                                return;
                            }

                            await share.Files.WriteAllBytesAsync(pagingDirectory + "/" + CreateLongEntryName(index), new byte[] { (byte)index }, cancellationToken).ConfigureAwait(false);
                        }
                    }, cancellationToken);
                }

                await Task.WhenAll(creators).ConfigureAwait(false);
                OpenCifsClientDirectoryEntry[] pagingEntries = await share.Directories.EnumerateAsync(pagingDirectory, cancellationToken: cancellationToken).ConfigureAwait(false);
                result.PagingEntryCount = pagingEntries.Length;
                result.DotEntriesExcluded = pagingEntries.All(entry => entry.FileName != "." && entry.FileName != "..");
                Require(pagingEntries.Length == PagingEntryCount, "Expected all " + PagingEntryCount + " entries across QUERY_DIRECTORY pages but found " + pagingEntries.Length + ".");
                Require(pagingEntries.Select(entry => entry.FileName).Distinct(StringComparer.OrdinalIgnoreCase).Count() == PagingEntryCount, "Expected no duplicate entries across pages.");
                Require(result.DotEntriesExcluded, "Expected '.' and '..' to be excluded from enumeration.");
                OpenCifsClientDirectoryEntry[] filtered = await share.Directories.EnumerateAsync(pagingDirectory, "*.dat", cancellationToken).ConfigureAwait(false);
                result.PagingFilteredEntryCount = filtered.Length;
                Require(filtered.Length == PagingEntryCount / 2, "Expected the filtered enumeration to return every matching entry across pages.");

                // Directory-entry flags and timestamps against metadata.
                DateTime lastWrite = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);
                await share.Metadata.SetBasicInfoAsync(root + "/exists.txt", lastWriteTimeUtc: lastWrite, cancellationToken: cancellationToken).ConfigureAwait(false);
                OpenCifsClientDirectoryEntry[] rootEntries = await share.Directories.EnumerateAsync(root, cancellationToken: cancellationToken).ConfigureAwait(false);
                OpenCifsClientDirectoryEntry fileEntry = rootEntries.Single(entry => entry.FileName == "exists.txt");
                OpenCifsClientDirectoryEntry directoryEntry = rootEntries.Single(entry => entry.FileName == "nested");
                OpenCifsClientFileMetadata fileMetadata = await share.Metadata.GetAttributesAsync(root + "/exists.txt", cancellationToken).ConfigureAwait(false);
                Require(!fileEntry.IsDirectory && directoryEntry.IsDirectory, "Expected IsDirectory to distinguish files from directories.");
                Require(fileEntry.LastWriteTimeUtc == lastWrite, "Expected the enumerated last-write time to match the value set through SetBasicInfoAsync.");
                Require(fileEntry.CreationTimeUtc.HasValue && fileEntry.ChangeTimeUtc.HasValue && fileEntry.LastAccessTimeUtc.HasValue, "Expected Samba to report every directory-entry timestamp.");
                Require(fileEntry.LastWriteTimeUtc == fileMetadata.LastWriteTimeUtc && fileEntry.CreationTimeUtc == fileMetadata.CreationTimeUtc, "Expected enumeration and metadata timestamps to agree.");
                result.TimestampsVerified = true;

                // Concurrent mixed operations on the single share session.
                Task[] workers = new Task[ConcurrentWorkers];

                for (int worker = 0; worker < workers.Length; worker++)
                {
                    int workerIndex = worker;
                    workers[worker] = Task.Run(async () =>
                    {
                        string workerDirectory = root + "/concurrent/w" + workerIndex.ToString(CultureInfo.InvariantCulture);
                        await share.Directories.CreateAsync(workerDirectory, createParents: true, cancellationToken).ConfigureAwait(false);

                        for (int iteration = 0; iteration < 3; iteration++)
                        {
                            byte[] payload = CreatePatternBytes(1000 + (workerIndex * 9973) + (iteration * 131071), workerIndex + iteration);
                            string path = workerDirectory + "/data.bin";
                            await share.Files.WriteAllBytesAsync(path, payload, cancellationToken).ConfigureAwait(false);
                            RequireEqual(payload, await share.Files.ReadAllBytesAsync(path, cancellationToken).ConfigureAwait(false), "Expected concurrent read-back of each worker's own payload.");
                            Require((await share.Metadata.GetAttributesAsync(path, cancellationToken).ConfigureAwait(false)).EndOfFile == (ulong)payload.Length, "Expected concurrent metadata to describe each worker's own file.");
                            OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync(workerDirectory, cancellationToken: cancellationToken).ConfigureAwait(false);
                            Require(entries.Length == 1 && entries[0].EndOfFile == (ulong)payload.Length, "Expected concurrent enumeration to describe each worker's own directory.");
                            RequireEqual(payload.AsSpan(100, 500).ToArray(), await share.Files.ReadAsync(path, 100, 500, cancellationToken).ConfigureAwait(false), "Expected concurrent ranged reads to return each worker's own bytes.");
                        }
                    }, cancellationToken);
                }

                await Task.WhenAll(workers).ConfigureAwait(false);
                result.ConcurrentWorkers = ConcurrentWorkers;
                await client.EchoAsync(cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                try
                {
                    await DeleteTreeAsync(share, root, cancellationToken).ConfigureAwait(false);
                    result.CleanupSucceeded = !await share.Metadata.ExistsAsync(root, cancellationToken).ConfigureAwait(false);
                }
                catch (OpenCifsClientException)
                {
                    result.CleanupSucceeded = false;
                }
            }

            Require(result.CleanupSucceeded, "Expected the primary-surface Samba run to remove its directory tree.");
            stopwatch.Stop();
            result.DurationMs = stopwatch.ElapsedMilliseconds;
            result.Passed = true;
            return result;
        }

        private static async Task DeleteTreeAsync(OpenCifsShareSession share, string path, CancellationToken cancellationToken)
        {
            if (!await share.Metadata.ExistsAsync(path, cancellationToken).ConfigureAwait(false))
            {
                return;
            }

            OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync(path, cancellationToken: cancellationToken).ConfigureAwait(false);

            foreach (OpenCifsClientDirectoryEntry entry in entries)
            {
                string child = path + "/" + entry.FileName;

                if (entry.IsDirectory)
                {
                    await DeleteTreeAsync(share, child, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    await share.Files.DeleteAsync(child, cancellationToken).ConfigureAwait(false);
                }
            }

            await share.Directories.DeleteAsync(path, cancellationToken).ConfigureAwait(false);
        }

        private static async Task<byte[]> ReadToEndAsync(Stream stream, int bufferSize, CancellationToken cancellationToken)
        {
            using MemoryStream destination = new MemoryStream();
            byte[] buffer = new byte[bufferSize];

            while (true)
            {
                int read = await stream.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);

                if (read == 0)
                {
                    return destination.ToArray();
                }

                destination.Write(buffer, 0, read);
            }
        }

        private static string CreateLongEntryName(int index)
        {
            return "entry-" + new string('n', 110) + "-" + index.ToString("D5", CultureInfo.InvariantCulture) + (index % 2 == 0 ? ".dat" : ".txt");
        }

        private static byte[] CreatePatternBytes(int length, int seed)
        {
            byte[] bytes = new byte[length];

            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)((index * 31) + (index >> 8) + seed));
            }

            return bytes;
        }

        private static void Require(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException(message);
            }
        }

        private static void RequireEqual(byte[] expected, byte[] actual, string message)
        {
            if (!expected.AsSpan().SequenceEqual(actual))
            {
                throw new InvalidOperationException(message + " Expected " + expected.Length + " bytes but received " + actual.Length + " bytes or different content.");
            }
        }

        private sealed class NonSeekableStream : Stream
        {
            internal NonSeekableStream(byte[] data, int maximumReadLength)
            {
                _Inner = new MemoryStream(data, writable: false);
                _MaximumReadLength = maximumReadLength;
            }

            public override bool CanRead
            {
                get
                {
                    return true;
                }
            }

            public override bool CanSeek
            {
                get
                {
                    return false;
                }
            }

            public override bool CanWrite
            {
                get
                {
                    return false;
                }
            }

            public override long Length
            {
                get
                {
                    throw new NotSupportedException();
                }
            }

            public override long Position
            {
                get
                {
                    throw new NotSupportedException();
                }
                set
                {
                    throw new NotSupportedException();
                }
            }

            public override void Flush()
            {
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return _Inner.Read(buffer, offset, Math.Min(count, _MaximumReadLength));
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                throw new NotSupportedException();
            }

            public override void SetLength(long value)
            {
                throw new NotSupportedException();
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                throw new NotSupportedException();
            }

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

    /// <summary>
    /// Primary-surface Samba interop evidence.
    /// </summary>
    internal sealed class SambaInteropPrimarySurfaceResult
    {
        public bool Passed { get; set; }

        public string Share { get; set; } = string.Empty;

        public string Directory { get; set; } = string.Empty;

        public long DurationMs { get; set; }

        public bool CreateParentsVerified { get; set; }

        public bool ExistsVerified { get; set; }

        public bool ZeroLengthVerified { get; set; }

        public bool ReadOnlyVerified { get; set; }

        public int LargeTransferBytes { get; set; }

        public bool StreamReadVerified { get; set; }

        public bool StreamWriteVerified { get; set; }

        public int PagingEntryCount { get; set; }

        public int PagingFilteredEntryCount { get; set; }

        public bool DotEntriesExcluded { get; set; }

        public bool TimestampsVerified { get; set; }

        public int ConcurrentWorkers { get; set; }

        public bool CleanupSucceeded { get; set; }
    }
}
