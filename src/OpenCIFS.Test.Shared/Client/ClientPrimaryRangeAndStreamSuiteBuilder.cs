namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Reflection;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientPrimaryDataTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;

    /// <summary>
    /// Primary-surface coverage for the 0.1.1 ranged-read, streamed-read, streamed-write, existence, recursive-create,
    /// and enriched directory-entry APIs.
    /// </summary>
    internal static class ClientPrimaryRangeAndStreamSuiteBuilder
    {
        private const string SuiteId = "Client.PrimaryRangeAndStream";
        private const int MiB = 1024 * 1024;

        /// <summary>
        /// Build the primary-surface ranged and streamed I/O suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientPrimaryRangeAndStreamSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: SuiteId,
                displayName: "Client primary ranged, streamed, existence, recursive-create, and directory-entry APIs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryExposesVersion011ApiSignatures",
                        displayName: "Client primary surface exposes the exact 0.1.1 API signatures and Try companions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            AssertMethod(typeof(OpenCifsShareFileOperations), "ReadAsync", typeof(Task<byte[]>), typeof(string), typeof(ulong), typeof(int), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareFileOperations), "TryReadAsync", typeof(Task<OpenCifsClientResult<byte[]>>), typeof(string), typeof(ulong), typeof(int), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareFileOperations), "OpenReadAsync", typeof(Task<Stream>), typeof(string), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareFileOperations), "TryOpenReadAsync", typeof(Task<OpenCifsClientResult<Stream>>), typeof(string), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareFileOperations), "WriteAsync", typeof(Task), typeof(string), typeof(Stream), typeof(long?), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareFileOperations), "TryWriteAsync", typeof(Task<OpenCifsClientResult>), typeof(string), typeof(Stream), typeof(long?), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareMetadataOperations), "ExistsAsync", typeof(Task<bool>), typeof(string), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareMetadataOperations), "TryExistsAsync", typeof(Task<OpenCifsClientResult<bool>>), typeof(string), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareDirectoryOperations), "CreateAsync", typeof(Task), typeof(string), typeof(bool), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareDirectoryOperations), "TryCreateAsync", typeof(Task<OpenCifsClientResult>), typeof(string), typeof(bool), typeof(CancellationToken));
                            AssertMethod(typeof(OpenCifsShareDirectoryOperations), "CreateAsync", typeof(Task), typeof(string), typeof(CancellationToken));

                            PropertyInfo? isDirectory = typeof(OpenCifsClientDirectoryEntry).GetProperty(nameof(OpenCifsClientDirectoryEntry.IsDirectory));
                            TestAssertions.True(isDirectory != null && isDirectory.PropertyType == typeof(bool) && isDirectory.CanRead && !isDirectory.CanWrite, "Expected a read-only bool IsDirectory directory-entry property.");

                            foreach (string name in new[] { "CreationTimeUtc", "LastAccessTimeUtc", "LastWriteTimeUtc", "ChangeTimeUtc" })
                            {
                                PropertyInfo? property = typeof(OpenCifsClientDirectoryEntry).GetProperty(name);
                                TestAssertions.True(property != null && property.PropertyType == typeof(DateTime?) && property.CanRead && property.CanWrite, "Expected a settable DateTime? directory-entry property named " + name + ".");
                            }

                            OpenCifsClientDirectoryEntry entry = new OpenCifsClientDirectoryEntry { FileAttributes = FileAttributes.Directory | FileAttributes.Hidden };
                            TestAssertions.True(entry.IsDirectory, "Expected IsDirectory to follow the Directory attribute flag.");
                            entry.FileAttributes = FileAttributes.Archive;
                            TestAssertions.False(entry.IsDirectory, "Expected IsDirectory to be false without the Directory attribute flag.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryRangedReadReturnsRequestedRangesAndPartialReadsAtEof",
                        displayName: "Client primary ranged read returns requested ranges across chunk boundaries and partial or empty results at EOF",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryRange_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                byte[] content = CreatePatternBytes((3 * MiB) + 12345, seed: 21);
                                File.WriteAllBytes(Path.Combine(sharePath, "range.bin"), content);
                                File.WriteAllBytes(Path.Combine(sharePath, "empty.bin"), Array.Empty<byte>());

                                await AssertRangeAsync(share, content, 0, 100, token).ConfigureAwait(false);
                                await AssertRangeAsync(share, content, 1000, 5000, token).ConfigureAwait(false);
                                await AssertRangeAsync(share, content, MiB - 10, 20, token).ConfigureAwait(false);
                                await AssertRangeAsync(share, content, 17, (2 * MiB) + 500000, token).ConfigureAwait(false);
                                await AssertRangeAsync(share, content, content.Length - 50, 50, token).ConfigureAwait(false);

                                byte[] tail = await share.Files.ReadAsync("range.bin", (ulong)(content.Length - 30), 1000, token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(content.AsSpan(content.Length - 30), tail, "Expected a range that crosses EOF to return only the remaining bytes.");

                                byte[] atEof = await share.Files.ReadAsync("range.bin", (ulong)content.Length, 10, token).ConfigureAwait(false);
                                TestAssertions.Equal(0, atEof.Length, "Expected a read at EOF to return an empty array.");

                                byte[] pastEof = await share.Files.ReadAsync("range.bin", (ulong)content.Length + 4096, 10, token).ConfigureAwait(false);
                                TestAssertions.Equal(0, pastEof.Length, "Expected a read beyond EOF to return an empty array.");

                                byte[] zeroCount = await share.Files.ReadAsync("range.bin", 10, 0, token).ConfigureAwait(false);
                                TestAssertions.Equal(0, zeroCount.Length, "Expected a zero-count read to return an empty array.");

                                byte[] hugeCount = await share.Files.ReadAsync("range.bin", 0, int.MaxValue, token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(content, hugeCount, "Expected an oversized count to be bounded by EOF instead of allocating the requested size.");

                                byte[] emptyFile = await share.Files.ReadAsync("empty.bin", 0, 10, token).ConfigureAwait(false);
                                TestAssertions.Equal(0, emptyFile.Length, "Expected a ranged read of a zero-length file to return an empty array.");

                                OpenCifsClientResult<byte[]> tryResult = await share.Files.TryReadAsync("range.bin", 5, 7, token).ConfigureAwait(false);
                                TestAssertions.True(tryResult.IsSuccess, "Expected TryReadAsync to succeed for an existing file.");
                                TestAssertions.SequenceEqual(content.AsSpan(5, 7), tryResult.GetValueOrThrow(), "Expected TryReadAsync to preserve the requested range.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryRangedReadRejectsNegativeCountMissingFilesDirectoriesAndCancellation",
                        displayName: "Client primary ranged read rejects negative counts, missing files, directories, and cancelled tokens",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryRangeNegative_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                File.WriteAllBytes(Path.Combine(sharePath, "file.bin"), CreatePatternBytes(100));
                                Directory.CreateDirectory(Path.Combine(sharePath, "folder"));

                                await TestAssertions.ThrowsAsync<ArgumentOutOfRangeException>(
                                    () => share.Files.ReadAsync("file.bin", 0, -1, token),
                                    "Expected a negative count to be rejected.").ConfigureAwait(false);
                                await TestAssertions.ThrowsAsync<ArgumentOutOfRangeException>(
                                    () => share.Files.TryReadAsync("file.bin", 0, -1, token),
                                    "Expected TryReadAsync to preserve local argument-validation throws.").ConfigureAwait(false);

                                OpenCifsClientResult<byte[]> missing = await share.Files.TryReadAsync("missing.bin", 0, 10, token).ConfigureAwait(false);
                                TestAssertions.False(missing.IsSuccess, "Expected a ranged read of a missing file to fail.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missing.ErrorCategory!.Value, "Expected a missing-file ranged read to map to NotFound.");
                                await TestAssertions.ThrowsAsync<OpenCifsStatusException>(
                                    () => share.Files.ReadAsync("missing.bin", 0, 10, token),
                                    "Expected ReadAsync to throw a typed status exception for a missing file.").ConfigureAwait(false);

                                OpenCifsClientResult<byte[]> directory = await share.Files.TryReadAsync("folder", 0, 10, token).ConfigureAwait(false);
                                TestAssertions.False(directory.IsSuccess, "Expected a ranged read of a directory to fail.");
                                TestAssertions.True(directory.Exception is OpenCifsStatusException, "Expected a directory ranged read to fail with a typed status exception.");

                                using CancellationTokenSource cancelled = new CancellationTokenSource();
                                cancelled.Cancel();
                                await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                    () => share.Files.ReadAsync("file.bin", 0, 10, cancelled.Token),
                                    "Expected a cancelled token to cancel the ranged read.").ConfigureAwait(false);

                                byte[] stillWorks = await share.Files.ReadAsync("file.bin", 0, 10, token).ConfigureAwait(false);
                                TestAssertions.Equal(10, stillWorks.Length, "Expected the session to remain usable after rejected ranged reads.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryOpenReadStreamReadsSeeksAndReportsLength",
                        displayName: "Client primary OpenRead stream reads lazily, seeks, reports length, and returns partial reads at EOF",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryStreamRead_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                byte[] content = CreatePatternBytes((2 * MiB) + 777, seed: 5);
                                File.WriteAllBytes(Path.Combine(sharePath, "stream.bin"), content);
                                File.WriteAllBytes(Path.Combine(sharePath, "empty.bin"), Array.Empty<byte>());

                                await using (Stream stream = await share.Files.OpenReadAsync("stream.bin", token).ConfigureAwait(false))
                                {
                                    TestAssertions.True(stream.CanRead, "Expected the read stream to be readable.");
                                    TestAssertions.True(stream.CanSeek, "Expected the read stream to be seekable.");
                                    TestAssertions.False(stream.CanWrite, "Expected the read stream to be read-only.");
                                    TestAssertions.Equal((long)content.Length, stream.Length, "Expected the read stream length to match EOF at open time.");
                                    TestAssertions.Equal(0L, stream.Position, "Expected the read stream to start at position zero.");

                                    byte[] all = await ReadToEndAsync(stream, 7919, token).ConfigureAwait(false);
                                    TestAssertions.SequenceEqual(content, all, "Expected sequential stream reads to return the full content.");
                                    TestAssertions.Equal((long)content.Length, stream.Position, "Expected the position to advance to EOF.");

                                    TestAssertions.Equal(1000L, stream.Seek(1000, SeekOrigin.Begin), "Expected Seek(Begin) to return the new position.");
                                    byte[] slice = new byte[10];
                                    int sliceRead = await stream.ReadAsync(slice.AsMemory(), token).ConfigureAwait(false);
                                    TestAssertions.Equal(10, sliceRead, "Expected a small read after seeking to fill the buffer.");
                                    TestAssertions.SequenceEqual(content.AsSpan(1000, 10), slice, "Expected the bytes at the seeked offset.");

                                    TestAssertions.Equal(1005L, stream.Seek(-5, SeekOrigin.Current), "Expected Seek(Current) to move relative to the current position.");
                                    int single = stream.ReadByte();
                                    TestAssertions.Equal((int)content[1005], single, "Expected synchronous ReadByte to return the byte at the current position.");

                                    stream.Seek(-3, SeekOrigin.End);
                                    byte[] lastBytes = new byte[16];
                                    int lastRead = stream.Read(lastBytes, 0, lastBytes.Length);
                                    TestAssertions.Equal(3, lastRead, "Expected a read near EOF to return only the remaining bytes.");
                                    TestAssertions.SequenceEqual(content.AsSpan(content.Length - 3), lastBytes.AsSpan(0, 3), "Expected the final bytes of the file.");
                                    TestAssertions.Equal(0, stream.Read(lastBytes, 0, lastBytes.Length), "Expected a read at EOF to return zero.");

                                    stream.Position = content.Length + 5000L;
                                    TestAssertions.Equal(0, await stream.ReadAsync(lastBytes.AsMemory(), token).ConfigureAwait(false), "Expected a read after seeking beyond EOF to return zero.");

                                    stream.Position = MiB - 3;
                                    using MemoryStream copy = new MemoryStream();
                                    await stream.CopyToAsync(copy, token).ConfigureAwait(false);
                                    TestAssertions.SequenceEqual(content.AsSpan(MiB - 3), copy.ToArray(), "Expected CopyToAsync from a mid-file position to return the remaining content.");

                                    await TestAssertions.ThrowsAsync<OpenCifsStatusException>(
                                        () => share.Files.WriteAllBytesAsync("stream.bin", new byte[] { 1 }, token),
                                        "Expected the read stream's share-read handle to block a concurrent overwrite.").ConfigureAwait(false);
                                }

                                await share.Files.WriteAllBytesAsync("stream.bin", new byte[] { 1, 2, 3 }, token).ConfigureAwait(false);
                                AssertBytes(new byte[] { 1, 2, 3 }, await share.Files.ReadAllBytesAsync("stream.bin", token).ConfigureAwait(false), "Expected the handle to be closed after the stream was disposed.");

                                using (Stream empty = await share.Files.OpenReadAsync("empty.bin", token).ConfigureAwait(false))
                                {
                                    TestAssertions.Equal(0L, empty.Length, "Expected a zero-length file stream to report zero length.");
                                    TestAssertions.Equal(0, empty.Read(new byte[8], 0, 8), "Expected a zero-length file stream to return EOF immediately.");
                                }

                                OpenCifsClientResult<Stream> tryResult = await share.Files.TryOpenReadAsync("stream.bin", token).ConfigureAwait(false);
                                TestAssertions.True(tryResult.IsSuccess, "Expected TryOpenReadAsync to succeed for an existing file.");
                                await using (Stream tryStream = tryResult.GetValueOrThrow())
                                {
                                    AssertBytes(new byte[] { 1, 2, 3 }, await ReadToEndAsync(tryStream, 64, token).ConfigureAwait(false), "Expected the TryOpenReadAsync stream to read the file.");
                                }

                                await share.Files.DeleteAsync("stream.bin", token).ConfigureAwait(false);
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryOpenReadStreamRejectsWritesSeekBeforeStartDisposalAndMissingFiles",
                        displayName: "Client primary OpenRead stream rejects writes, seeks before start, use after disposal, missing files, and directories",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryStreamNegative_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                File.WriteAllBytes(Path.Combine(sharePath, "file.bin"), CreatePatternBytes(4096));
                                Directory.CreateDirectory(Path.Combine(sharePath, "folder"));

                                Stream stream = await share.Files.OpenReadAsync("file.bin", token).ConfigureAwait(false);
                                TestAssertions.Throws<NotSupportedException>(() => stream.Write(new byte[1], 0, 1), "Expected writes to be rejected.");
                                await TestAssertions.ThrowsAsync<NotSupportedException>(() => stream.WriteAsync(new byte[1], 0, 1, token), "Expected async writes to be rejected.").ConfigureAwait(false);
                                TestAssertions.Throws<NotSupportedException>(() => stream.SetLength(1), "Expected SetLength to be rejected.");
                                TestAssertions.Throws<IOException>(() => stream.Seek(-1, SeekOrigin.Begin), "Expected a seek before the start to be rejected.");
                                TestAssertions.Throws<ArgumentOutOfRangeException>(() => stream.Position = -1, "Expected a negative position to be rejected.");

                                using (CancellationTokenSource cancelled = new CancellationTokenSource())
                                {
                                    cancelled.Cancel();
                                    await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                        () => stream.ReadAsync(new byte[16], 0, 16, cancelled.Token),
                                        "Expected a cancelled token to cancel a stream read.").ConfigureAwait(false);
                                }

                                stream.Dispose();
                                stream.Dispose();
                                await stream.DisposeAsync().ConfigureAwait(false);
                                TestAssertions.False(stream.CanRead, "Expected a disposed stream to report CanRead=false.");
                                TestAssertions.Throws<ObjectDisposedException>(() => stream.ReadExactly(new byte[4], 0, 4), "Expected reads after disposal to be rejected.");
                                TestAssertions.Throws<ObjectDisposedException>(() => stream.Seek(0, SeekOrigin.Begin), "Expected seeks after disposal to be rejected.");
                                await share.Files.DeleteAsync("file.bin", token).ConfigureAwait(false);

                                OpenCifsClientResult<Stream> missing = await share.Files.TryOpenReadAsync("missing.bin", token).ConfigureAwait(false);
                                TestAssertions.False(missing.IsSuccess, "Expected OpenRead of a missing file to fail.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missing.ErrorCategory!.Value, "Expected OpenRead of a missing file to map to NotFound.");
                                await TestAssertions.ThrowsAsync<OpenCifsStatusException>(
                                    () => share.Files.OpenReadAsync("folder", token),
                                    "Expected OpenRead of a directory to fail with a typed status exception.").ConfigureAwait(false);

                                File.WriteAllBytes(Path.Combine(sharePath, "orphan.bin"), CreatePatternBytes(4096));
                                Stream orphan = await share.Files.OpenReadAsync("orphan.bin", token).ConfigureAwait(false);
                                await share.DisposeAsync().ConfigureAwait(false);
                                await TestAssertions.ThrowsAsync<OpenCifsClientStateException>(
                                    () => orphan.ReadAsync(new byte[16], 0, 16, token),
                                    "Expected a stream read after its share session closed to fail with a client-state exception.").ConfigureAwait(false);
                                await orphan.DisposeAsync().ConfigureAwait(false);
                                await client.DisposeAsync().ConfigureAwait(false);
                                orphan.Dispose();
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryStreamWriteCreatesAndOverwritesFromSeekableAndNonSeekableSources",
                        displayName: "Client primary stream write creates and overwrites files from seekable and non-seekable sources with exact or open-ended lengths",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryStreamWrite_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                byte[] large = CreatePatternBytes((3 * MiB) + 99, seed: 31);
                                using (MemoryStream source = new MemoryStream(large))
                                {
                                    await share.Files.WriteAsync("upload.bin", source, cancellationToken: token).ConfigureAwait(false);
                                }

                                TestAssertions.SequenceEqual(large, File.ReadAllBytes(Path.Combine(sharePath, "upload.bin")), "Expected an open-ended stream write to persist the full source.");

                                byte[] smaller = CreatePatternBytes(250000, seed: 37);
                                using (NonSeekableReadStream source = new NonSeekableReadStream(smaller, maximumReadLength: 4093))
                                {
                                    await share.Files.WriteAsync("upload.bin", source, cancellationToken: token).ConfigureAwait(false);
                                }

                                AssertBytes(smaller, await share.Files.ReadAllBytesAsync("upload.bin", token).ConfigureAwait(false), "Expected a non-seekable overwrite to truncate the previous, larger content.");

                                byte[] partialSource = CreatePatternBytes(10000, seed: 41);
                                using (NonSeekableReadStream source = new NonSeekableReadStream(partialSource, maximumReadLength: 333))
                                {
                                    await share.Files.WriteAsync("exact.bin", source, 6000, token).ConfigureAwait(false);
                                }

                                AssertBytes(partialSource.AsSpan(0, 6000).ToArray(), await share.Files.ReadAllBytesAsync("exact.bin", token).ConfigureAwait(false), "Expected an exact-length write to stop after the requested byte count.");

                                using (MemoryStream source = new MemoryStream(large))
                                {
                                    await share.Files.WriteAsync("exact-large.bin", source, large.Length, token).ConfigureAwait(false);
                                }

                                AssertBytes(large, await share.Files.ReadAllBytesAsync("exact-large.bin", token).ConfigureAwait(false), "Expected an exact-length multi-chunk write to persist every byte.");

                                using (MemoryStream source = new MemoryStream(partialSource))
                                {
                                    await share.Files.WriteAsync("exact.bin", source, 0, token).ConfigureAwait(false);
                                }

                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "exact.bin")).Length, "Expected a zero-length write to truncate the file to empty.");

                                using (MemoryStream source = new MemoryStream())
                                {
                                    await share.Files.WriteAsync("empty.bin", source, cancellationToken: token).ConfigureAwait(false);
                                }

                                TestAssertions.True(await share.Metadata.ExistsAsync("empty.bin", token).ConfigureAwait(false), "Expected an empty source to create the file.");
                                TestAssertions.Equal(0, (await share.Files.ReadAllBytesAsync("empty.bin", token).ConfigureAwait(false)).Length, "Expected an empty source to produce an empty file.");

                                using (MemoryStream source = new MemoryStream(new byte[] { 9, 8, 7 }))
                                {
                                    OpenCifsClientResult result = await share.Files.TryWriteAsync("try.bin", source, cancellationToken: token).ConfigureAwait(false);
                                    TestAssertions.True(result.IsSuccess, "Expected TryWriteAsync to succeed.");
                                }

                                AssertBytes(new byte[] { 9, 8, 7 }, await share.Files.ReadAllBytesAsync("try.bin", token).ConfigureAwait(false), "Expected TryWriteAsync to persist its source.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryStreamWriteRejectsShortSourcesInvalidArgumentsAndMissingParents",
                        displayName: "Client primary stream write rejects short sources, invalid arguments, missing parents, directories, and cancelled tokens",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryStreamWriteNegative_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                                byte[] source = CreatePatternBytes(1000);

                                using (NonSeekableReadStream shortSource = new NonSeekableReadStream(source, maximumReadLength: 100))
                                {
                                    await TestAssertions.ThrowsAsync<EndOfStreamException>(
                                        () => share.Files.WriteAsync("short.bin", shortSource, 2000, token),
                                        "Expected a source shorter than the requested length to throw EndOfStreamException.").ConfigureAwait(false);
                                }

                                await share.Files.DeleteAsync("short.bin", token).ConfigureAwait(false);
                                TestAssertions.False(await share.Metadata.ExistsAsync("short.bin", token).ConfigureAwait(false), "Expected the handle to be closed after a short-source failure so the partial file can be deleted.");

                                await TestAssertions.ThrowsAsync<ArgumentNullException>(
                                    () => share.Files.WriteAsync("null.bin", null!, cancellationToken: token),
                                    "Expected a null source to be rejected.").ConfigureAwait(false);

                                using (MemoryStream valid = new MemoryStream(source))
                                {
                                    await TestAssertions.ThrowsAsync<ArgumentOutOfRangeException>(
                                        () => share.Files.WriteAsync("negative.bin", valid, -1, token),
                                        "Expected a negative length to be rejected.").ConfigureAwait(false);
                                    await TestAssertions.ThrowsAsync<ArgumentOutOfRangeException>(
                                        () => share.Files.TryWriteAsync("negative.bin", valid, -1, token),
                                        "Expected TryWriteAsync to preserve local argument-validation throws.").ConfigureAwait(false);
                                }

                                using (FileStream writeOnly = new FileStream(Path.Combine(Path.GetTempPath(), "OpenCifsWriteOnly_" + Guid.NewGuid().ToString("N")), FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.DeleteOnClose))
                                {
                                    await TestAssertions.ThrowsAsync<ArgumentException>(
                                        () => share.Files.WriteAsync("unreadable.bin", writeOnly, cancellationToken: token),
                                        "Expected an unreadable source to be rejected.").ConfigureAwait(false);
                                }

                                using (MemoryStream valid = new MemoryStream(source))
                                {
                                    OpenCifsClientResult missingParent = await share.Files.TryWriteAsync("missing-parent\\child.bin", valid, cancellationToken: token).ConfigureAwait(false);
                                    TestAssertions.False(missingParent.IsSuccess, "Expected a write beneath a missing parent directory to fail.");
                                    TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingParent.ErrorCategory!.Value, "Expected a missing parent to map to NotFound.");
                                }

                                using (MemoryStream valid = new MemoryStream(source))
                                {
                                    OpenCifsClientResult directory = await share.Files.TryWriteAsync("folder", valid, cancellationToken: token).ConfigureAwait(false);
                                    TestAssertions.False(directory.IsSuccess, "Expected a stream write targeting a directory to fail.");
                                }

                                using (MemoryStream valid = new MemoryStream(source))
                                using (CancellationTokenSource cancelled = new CancellationTokenSource())
                                {
                                    cancelled.Cancel();
                                    await TestAssertions.ThrowsAsync<OperationCanceledException>(
                                        () => share.Files.WriteAsync("cancelled.bin", valid, cancellationToken: cancelled.Token),
                                        "Expected a cancelled token to cancel the stream write.").ConfigureAwait(false);
                                }

                                await client.EchoAsync(token).ConfigureAwait(false);
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryRangedAndStreamedReadsContinueAcrossShortServerReads",
                        displayName: "Client primary ranged and streamed reads continue across legal short server reads",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryShortRange_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                byte[] content = CreatePatternBytes(200003, seed: 43);
                                File.WriteAllBytes(Path.Combine(sharePath, "short.bin"), content);
                                byte[] range = await share.Files.ReadAsync("short.bin", 1234, 150000, token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(content.AsSpan(1234, 150000), range, "Expected a ranged read to continue across short server reads.");

                                await using Stream stream = await share.Files.OpenReadAsync("short.bin", token).ConfigureAwait(false);
                                AssertBytes(content, await ReadToEndAsync(stream, 65536, token).ConfigureAwait(false), "Expected a streamed read to continue across short server reads.");
                            },
                            maximumDialect: SmbDialect.Smb2002,
                            backendFactory: sharePath => new ShortReadShareBackend(TestEnvironmentDefaults.DefaultShareName, sharePath, maximumReadLength: 5000))),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryExistsReportsFilesDirectoriesAndMissingPaths",
                        displayName: "Client primary exists reports files and directories as present and missing paths as absent",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryExists_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                Directory.CreateDirectory(Path.Combine(sharePath, "folder", "nested"));
                                File.WriteAllBytes(Path.Combine(sharePath, "folder", "file.txt"), new byte[] { 1 });
                                File.WriteAllBytes(Path.Combine(sharePath, "empty.txt"), Array.Empty<byte>());

                                TestAssertions.True(await share.Metadata.ExistsAsync("folder\\file.txt", token).ConfigureAwait(false), "Expected an existing file to exist.");
                                TestAssertions.True(await share.Metadata.ExistsAsync("/folder/file.txt", token).ConfigureAwait(false), "Expected forward-slash paths to resolve.");
                                TestAssertions.True(await share.Metadata.ExistsAsync("empty.txt", token).ConfigureAwait(false), "Expected a zero-length file to exist.");
                                TestAssertions.True(await share.Metadata.ExistsAsync("folder", token).ConfigureAwait(false), "Expected an existing directory to exist.");
                                TestAssertions.True(await share.Metadata.ExistsAsync("folder\\nested", token).ConfigureAwait(false), "Expected an existing nested directory to exist.");
                                TestAssertions.False(await share.Metadata.ExistsAsync("missing.txt", token).ConfigureAwait(false), "Expected a missing file not to exist.");
                                TestAssertions.False(await share.Metadata.ExistsAsync("missing\\child.txt", token).ConfigureAwait(false), "Expected a path beneath a missing directory not to exist.");
                                TestAssertions.False(await share.Metadata.ExistsAsync("folder\\file.txt\\child", token).ConfigureAwait(false), "Expected a path beneath a file not to exist.");

                                OpenCifsClientResult<bool> tryExists = await share.Metadata.TryExistsAsync("folder", token).ConfigureAwait(false);
                                TestAssertions.True(tryExists.IsSuccess && tryExists.GetValueOrThrow(), "Expected TryExistsAsync to report an existing directory.");
                                OpenCifsClientResult<bool> tryMissing = await share.Metadata.TryExistsAsync("missing.txt", token).ConfigureAwait(false);
                                TestAssertions.True(tryMissing.IsSuccess && !tryMissing.GetValueOrThrow(), "Expected TryExistsAsync to report a missing file as a successful false.");

                                await client.DisconnectAsync(token).ConfigureAwait(false);
                                OpenCifsClientResult<bool> afterDisconnect = await share.Metadata.TryExistsAsync("folder", token).ConfigureAwait(false);
                                TestAssertions.False(afterDisconnect.IsSuccess, "Expected TryExistsAsync to fail after disconnect instead of reporting absence.");
                                TestAssertions.True(afterDisconnect.Exception is OpenCifsClientStateException, "Expected a client-state failure after disconnect.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryReadsReturnContentForReadOnlyFilesAndRejectOverwrites",
                        displayName: "Client primary whole-file, ranged, and streamed reads return content for read-only files, overwrites are rejected, and the read-only attribute can be cleared",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryReadOnly_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                byte[] content = CreatePatternBytes(150000, seed: 53);
                                await share.Files.WriteAllBytesAsync("readonly.bin", content, token).ConfigureAwait(false);
                                await share.Metadata.SetBasicInfoAsync("readonly.bin", fileAttributes: FileAttributes.ReadOnly, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.True((File.GetAttributes(Path.Combine(sharePath, "readonly.bin")) & System.IO.FileAttributes.ReadOnly) != 0, "Expected the backing file to be read-only.");

                                try
                                {
                                    AssertBytes(content, await share.Files.ReadAllBytesAsync("readonly.bin", token).ConfigureAwait(false), "Expected ReadAllBytes to read a read-only file.");
                                    AssertBytes(content.AsSpan(10, 20).ToArray(), await share.Files.ReadAsync("readonly.bin", 10, 20, token).ConfigureAwait(false), "Expected ReadAsync to read a read-only file.");
                                    await using (Stream stream = await share.Files.OpenReadAsync("readonly.bin", token).ConfigureAwait(false))
                                    {
                                        AssertBytes(content, await ReadToEndAsync(stream, 65536, token).ConfigureAwait(false), "Expected OpenReadAsync to read a read-only file.");
                                    }

                                    TestAssertions.True(await share.Metadata.ExistsAsync("readonly.bin", token).ConfigureAwait(false), "Expected a read-only file to exist.");
                                    OpenCifsClientResult overwrite = await share.Files.TryWriteAllBytesAsync("readonly.bin", new byte[] { 1 }, token).ConfigureAwait(false);
                                    TestAssertions.False(overwrite.IsSuccess, "Expected an overwrite of a read-only file to be rejected.");

                                    await share.Metadata.SetBasicInfoAsync("readonly.bin", fileAttributes: FileAttributes.Normal, cancellationToken: token).ConfigureAwait(false);
                                    TestAssertions.True((File.GetAttributes(Path.Combine(sharePath, "readonly.bin")) & System.IO.FileAttributes.ReadOnly) == 0, "Expected SetBasicInfoAsync to clear the read-only attribute of a read-only file.");
                                    await share.Files.WriteAllBytesAsync("readonly.bin", new byte[] { 7 }, token).ConfigureAwait(false);
                                    AssertBytes(new byte[] { 7 }, await share.Files.ReadAllBytesAsync("readonly.bin", token).ConfigureAwait(false), "Expected the file to be writable after clearing read-only.");
                                }
                                finally
                                {
                                    File.SetAttributes(Path.Combine(sharePath, "readonly.bin"), System.IO.FileAttributes.Normal);
                                }
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryShareRootEnumeratesExistsAndReportsDirectoryMetadata",
                        displayName: "Client primary share root enumerates, exists, and reports directory metadata for empty and separator-only paths",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryRoot_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                File.WriteAllBytes(Path.Combine(sharePath, "top.txt"), new byte[] { 1, 2 });
                                Directory.CreateDirectory(Path.Combine(sharePath, "topdir"));

                                foreach (string rootPath in new[] { string.Empty, "/", "\\" })
                                {
                                    OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync(rootPath, cancellationToken: token).ConfigureAwait(false);
                                    HashSet<string> names = GetNames(entries);
                                    TestAssertions.True(names.SetEquals(new[] { "top.txt", "topdir" }), "Expected share-root enumeration of '" + rootPath + "' to return exactly the root entries.");
                                    TestAssertions.True(await share.Metadata.ExistsAsync(rootPath, token).ConfigureAwait(false), "Expected the share root '" + rootPath + "' to exist.");
                                    OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync(rootPath, token).ConfigureAwait(false);
                                    TestAssertions.True(metadata.IsDirectory, "Expected share-root metadata for '" + rootPath + "' to report a directory.");
                                    await share.Directories.CreateAsync(rootPath, createParents: true, token).ConfigureAwait(false);
                                    await share.Directories.CreateAsync(rootPath, token).ConfigureAwait(false);
                                }

                                OpenCifsClientDirectoryEntry[] filtered = await share.Directories.EnumerateAsync(string.Empty, "*.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(1, filtered.Length, "Expected a filtered share-root enumeration to honor the pattern.");
                                await TestAssertions.ThrowsAsync<ArgumentNullException>(
                                    () => share.Metadata.ExistsAsync(null!, token),
                                    "Expected a null path to be rejected.").ConfigureAwait(false);
                                OpenCifsClientResult rootRename = await share.Files.TryRenameAsync("top.txt", "/", cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(rootRename.IsSuccess, "Expected a rename onto the share root to be rejected.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryCreateWithParentsCreatesMissingAncestorsIdempotentlyAndRejectsFileAncestors",
                        displayName: "Client primary create with parents creates missing ancestors idempotently and rejects file ancestors or missing parents without the flag",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryCreateParents_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                await share.Directories.CreateAsync("a/b/c/d", createParents: true, token).ConfigureAwait(false);
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "a", "b", "c", "d")), "Expected every missing ancestor and the target to be created.");

                                await share.Directories.CreateAsync("a\\b\\c\\d", createParents: true, token).ConfigureAwait(false);
                                await share.Directories.CreateAsync("a/b/e", createParents: true, token).ConfigureAwait(false);
                                await share.Directories.CreateAsync("a", createParents: true, token).ConfigureAwait(false);
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "a", "b", "e")), "Expected a sibling beneath existing ancestors to be created.");

                                OpenCifsClientResult tryResult = await share.Directories.TryCreateAsync("x/y", createParents: true, token).ConfigureAwait(false);
                                TestAssertions.True(tryResult.IsSuccess, "Expected TryCreateAsync with parents to succeed.");

                                OpenCifsClientResult withoutParents = await share.Directories.TryCreateAsync("m/n", createParents: false, token).ConfigureAwait(false);
                                TestAssertions.False(withoutParents.IsSuccess, "Expected create without parents to fail when the parent is missing.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "m")), "Expected create without parents not to create the missing parent.");

                                await share.Files.WriteAllBytesAsync("a/file.txt", new byte[] { 1 }, token).ConfigureAwait(false);
                                OpenCifsClientResult fileAncestor = await share.Directories.TryCreateAsync("a/file.txt/child", createParents: true, token).ConfigureAwait(false);
                                TestAssertions.False(fileAncestor.IsSuccess, "Expected create with parents to fail when an ancestor is a file.");
                                TestAssertions.True(fileAncestor.Exception is OpenCifsStatusException, "Expected a file-ancestor failure to preserve the typed status exception.");

                                OpenCifsClientResult fileTarget = await share.Directories.TryCreateAsync("a/file.txt", createParents: true, token).ConfigureAwait(false);
                                TestAssertions.False(fileTarget.IsSuccess, "Expected create with parents to fail when the target itself is a file.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryEnumerateReportsDirectoryFlagsAndTimestamps",
                        displayName: "Client primary enumerate reports IsDirectory and UTC timestamps that match metadata queries",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryEntryTimes_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                await share.Directories.CreateAsync("root/sub", createParents: true, token).ConfigureAwait(false);
                                await share.Files.WriteAllBytesAsync("root/file.bin", CreatePatternBytes(321), token).ConfigureAwait(false);
                                DateTime lastWrite = new DateTime(2024, 1, 2, 3, 4, 5, DateTimeKind.Utc);
                                DateTime creation = new DateTime(2023, 6, 7, 8, 9, 10, DateTimeKind.Utc);
                                await share.Metadata.SetBasicInfoAsync("root/file.bin", creationTimeUtc: creation, lastWriteTimeUtc: lastWrite, cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync("root", cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal(2, entries.Length, "Expected exactly the file and subdirectory without dot entries.");
                                OpenCifsClientDirectoryEntry file = entries.Single(entry => entry.FileName == "file.bin");
                                OpenCifsClientDirectoryEntry sub = entries.Single(entry => entry.FileName == "sub");
                                TestAssertions.False(file.IsDirectory, "Expected the file entry not to be a directory.");
                                TestAssertions.True(sub.IsDirectory, "Expected the subdirectory entry to be a directory.");
                                TestAssertions.Equal(321UL, file.EndOfFile, "Expected the file entry size.");
                                TestAssertions.Equal(lastWrite, file.LastWriteTimeUtc!.Value, "Expected the enumerated last-write time to match the value that was set.");
                                TestAssertions.Equal(creation, file.CreationTimeUtc!.Value, "Expected the enumerated creation time to match the value that was set.");
                                TestAssertions.Equal(DateTimeKind.Utc, file.LastWriteTimeUtc!.Value.Kind, "Expected enumerated timestamps to be UTC.");
                                TestAssertions.True(file.LastAccessTimeUtc.HasValue && file.ChangeTimeUtc.HasValue, "Expected the file entry to report access and change times.");
                                TestAssertions.True(sub.CreationTimeUtc.HasValue && sub.LastWriteTimeUtc.HasValue, "Expected the directory entry to report timestamps.");

                                OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("root/file.bin", token).ConfigureAwait(false);
                                TestAssertions.Equal(metadata.LastWriteTimeUtc, file.LastWriteTimeUtc, "Expected enumeration and metadata last-write times to agree.");
                                TestAssertions.Equal(metadata.CreationTimeUtc, file.CreationTimeUtc, "Expected enumeration and metadata creation times to agree.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryWriteAllBytesAndReadAllBytesRoundTripZeroLengthAndMultiMegabyteFiles",
                        displayName: "Client primary WriteAllBytes and ReadAllBytes round-trip zero-length and multi-megabyte files over large MTU",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryLargeAndEmpty_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                await share.Files.WriteAllBytesAsync("empty.bin", Array.Empty<byte>(), token).ConfigureAwait(false);
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "empty.bin")), "Expected an empty WriteAllBytes to create the file.");
                                TestAssertions.Equal(0, (await share.Files.ReadAllBytesAsync("empty.bin", token).ConfigureAwait(false)).Length, "Expected a zero-length file to read back empty.");

                                await share.Files.WriteAllBytesAsync("shrink.bin", CreatePatternBytes(5000), token).ConfigureAwait(false);
                                await share.Files.WriteAllBytesAsync("shrink.bin", Array.Empty<byte>(), token).ConfigureAwait(false);
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "shrink.bin")).Length, "Expected an empty WriteAllBytes to truncate existing content.");

                                byte[] large = CreatePatternBytes((5 * MiB) + 3, seed: 47);
                                await share.Files.WriteAllBytesAsync("large.bin", large, token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(large, File.ReadAllBytes(Path.Combine(sharePath, "large.bin")), "Expected a multi-megabyte WriteAllBytes to persist every chunk.");
                                AssertBytes(large, await share.Files.ReadAllBytesAsync("large.bin", token).ConfigureAwait(false), "Expected a multi-megabyte ReadAllBytes to return every chunk.");
                                AssertBytes(large.AsSpan(MiB - 1, (2 * MiB) + 2).ToArray(), await share.Files.ReadAsync("large.bin", (ulong)(MiB - 1), (2 * MiB) + 2, token).ConfigureAwait(false), "Expected a multi-chunk ranged read to return the exact range.");
                                await client.EchoAsync(token).ConfigureAwait(false);
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryConcurrentStreamsRangesAndMetadataOnOneSessionRemainCorrelated",
                        displayName: "Client primary concurrent streams, ranged reads, stream writes, exists, and recursive creates on one session remain correlated",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryConcurrentStreams_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                const int Workers = 32;
                                Task[] tasks = new Task[Workers];

                                for (int worker = 0; worker < Workers; worker++)
                                {
                                    int workerIndex = worker;
                                    tasks[worker] = Task.Run(async () =>
                                    {
                                        string directory = "w" + workerIndex.ToString(System.Globalization.CultureInfo.InvariantCulture) + "/inner";
                                        await share.Directories.CreateAsync(directory, createParents: true, token).ConfigureAwait(false);
                                        byte[] payload = CreatePatternBytes(20000 + (workerIndex * 7717), seed: workerIndex);
                                        string path = directory + "/data.bin";

                                        using (NonSeekableReadStream source = new NonSeekableReadStream(payload, 8191))
                                        {
                                            await share.Files.WriteAsync(path, source, payload.Length, token).ConfigureAwait(false);
                                        }

                                        TestAssertions.True(await share.Metadata.ExistsAsync(path, token).ConfigureAwait(false), "Expected each worker's file to exist.");
                                        byte[] range = await share.Files.ReadAsync(path, 777, 5000, token).ConfigureAwait(false);
                                        TestAssertions.SequenceEqual(payload.AsSpan(777, 5000), range, "Expected each worker's ranged read to return its own bytes.");

                                        await using (Stream stream = await share.Files.OpenReadAsync(path, token).ConfigureAwait(false))
                                        {
                                            TestAssertions.Equal((long)payload.Length, stream.Length, "Expected each worker's stream length to describe its own file.");
                                            AssertBytes(payload, await ReadToEndAsync(stream, 30011, token).ConfigureAwait(false), "Expected each worker's stream to return its own content.");
                                        }
                                    }, token);
                                }

                                await Task.WhenAll(tasks).ConfigureAwait(false);
                                OpenCifsClientDirectoryEntry[] roots = await share.Directories.EnumerateAsync("\\", cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal(Workers, roots.Count(entry => entry.IsDirectory && entry.FileName.StartsWith("w", StringComparison.Ordinal)), "Expected every worker directory to exist.");
                            })),
                });
        }

        private static async Task AssertRangeAsync(OpenCifsShareSession share, byte[] content, int offset, int count, CancellationToken cancellationToken)
        {
            byte[] actual = await share.Files.ReadAsync("range.bin", (ulong)offset, count, cancellationToken).ConfigureAwait(false);
            TestAssertions.SequenceEqual(content.AsSpan(offset, count), actual, "Expected ReadAsync(" + offset + ", " + count + ") to return the exact range.");
        }

        private static void AssertBytes(byte[] expected, byte[] actual, string message)
        {
            TestAssertions.SequenceEqual(expected, actual, message);
        }

        private static void AssertMethod(Type type, string name, Type returnType, params Type[] parameterTypes)
        {
            MethodInfo? method = type.GetMethod(name, BindingFlags.Public | BindingFlags.Instance, binder: null, types: parameterTypes, modifiers: null);

            if (method == null)
            {
                throw new InvalidOperationException("Expected " + type.Name + "." + name + "(" + string.Join(", ", parameterTypes.Select(parameter => parameter.Name)) + ") to exist.");
            }

            TestAssertions.Equal(returnType, method.ReturnType, "Unexpected return type for " + type.Name + "." + name + ".");
            ParameterInfo[] parameters = method.GetParameters();
            ParameterInfo last = parameters[parameters.Length - 1];
            TestAssertions.True(last.ParameterType == typeof(CancellationToken) && last.HasDefaultValue, "Expected " + type.Name + "." + name + " to end with an optional CancellationToken.");
        }
    }
}
