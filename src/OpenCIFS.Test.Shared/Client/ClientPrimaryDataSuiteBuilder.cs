namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientPrimaryDataTestSupport;

    /// <summary>
    /// Primary-surface data-path coverage: multi-page directory enumeration, short-read handling,
    /// cancellation recovery, and concurrent use of one share session.
    /// </summary>
    internal static class ClientPrimaryDataSuiteBuilder
    {
        private const string SuiteId = "Client.PrimaryData";

        /// <summary>
        /// Build the primary-surface data-path suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientPrimaryDataSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: SuiteId,
                displayName: "Client primary data-path paging, short-read, cancellation, and concurrency behavior",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryEnumerateReturnsEveryEntryAcrossManyQueryDirectoryPages",
                        displayName: "Client primary enumerate returns every entry of a 1,600-entry long-name directory across many QUERY_DIRECTORY pages",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryPaging_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                string directoryPath = Path.Combine(sharePath, "big");
                                Directory.CreateDirectory(directoryPath);
                                HashSet<string> expectedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                                for (int index = 0; index < 1600; index++)
                                {
                                    string name = CreateLongEntryName(index % 2 == 0 ? "alpha" : "beta", index, index % 2 == 0 ? ".dat" : ".txt");
                                    File.WriteAllBytes(Path.Combine(directoryPath, name), new byte[] { (byte)index });
                                    expectedNames.Add(name);
                                }

                                Directory.CreateDirectory(Path.Combine(directoryPath, "child-directory"));
                                expectedNames.Add("child-directory");

                                OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync("big", cancellationToken: token).ConfigureAwait(false);
                                HashSet<string> actualNames = GetNames(entries);
                                TestAssertions.Equal(expectedNames.Count, entries.Length, "Expected enumeration to return every entry across all QUERY_DIRECTORY pages without duplicates.");
                                TestAssertions.True(actualNames.SetEquals(expectedNames), "Expected enumeration to return exactly the created entry names.");
                                TestAssertions.False(actualNames.Contains(".") || actualNames.Contains(".."), "Expected the primary enumeration surface to exclude '.' and '..'.");

                                OpenCifsClientDirectoryEntry[] filtered = await share.Directories.EnumerateAsync("big", "*.dat", token).ConfigureAwait(false);
                                TestAssertions.Equal(800, filtered.Length, "Expected a filtered enumeration to return every matching entry across pages.");
                                TestAssertions.True(filtered.All(entry => entry.FileName.EndsWith(".dat", StringComparison.OrdinalIgnoreCase)), "Expected the filtered enumeration to honor the search pattern on every page.");

                                OpenCifsClientDirectoryEntry[] none = await share.Directories.EnumerateAsync("big", "*.missing", token).ConfigureAwait(false);
                                TestAssertions.Equal(0, none.Length, "Expected a non-matching pattern to return an empty enumeration instead of failing.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryReadAllBytesReturnsFullContentWhenServerReturnsShortReads",
                        displayName: "Client primary ReadAllBytes returns full content when the server returns legal short reads before EOF",
                        executeAsync: async token =>
                        {
                            ShortReadShareBackend? backend = null;
                            await RunWithPrimaryShareAsync(
                                "OpenCifsPrimaryShortRead_",
                                token,
                                async (client, share, sharePath) =>
                                {
                                    byte[] small = CreatePatternBytes(50000, seed: 3);
                                    byte[] large = CreatePatternBytes(300001, seed: 7);
                                    File.WriteAllBytes(Path.Combine(sharePath, "small.bin"), small);
                                    File.WriteAllBytes(Path.Combine(sharePath, "large.bin"), large);

                                    byte[] smallRead = await share.Files.ReadAllBytesAsync("small.bin", token).ConfigureAwait(false);
                                    TestAssertions.SequenceEqual(small, smallRead, "Expected ReadAllBytes to keep reading after a short single-chunk read.");

                                    byte[] largeRead = await share.Files.ReadAllBytesAsync("large.bin", token).ConfigureAwait(false);
                                    TestAssertions.SequenceEqual(large, largeRead, "Expected ReadAllBytes to keep reading after short multi-chunk reads until EOF.");
                                    TestAssertions.True(backend!.ShortenedReadCount > 0, "Expected the short-read backend to have shortened at least one server read.");
                                },
                                maximumDialect: SmbDialect.Smb2002,
                                backendFactory: sharePath =>
                                {
                                    backend = new ShortReadShareBackend(TestEnvironmentDefaults.DefaultShareName, sharePath, maximumReadLength: 7000);
                                    return backend;
                                }).ConfigureAwait(false);
                        }),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryConnectionRemainsUsableAfterCancelledReads",
                        displayName: "Client primary connection remains usable after reads are cancelled while a response is outstanding",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryCancel_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                byte[] large = CreatePatternBytes(8 * 1024 * 1024, seed: 11);
                                byte[] small = CreatePatternBytes(1234, seed: 13);
                                File.WriteAllBytes(Path.Combine(sharePath, "large.bin"), large);
                                File.WriteAllBytes(Path.Combine(sharePath, "small.bin"), small);
                                int cancelledCount = 0;

                                for (int attempt = 0; attempt < 24; attempt++)
                                {
                                    using CancellationTokenSource cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                    cancellationTokenSource.CancelAfter(TimeSpan.FromMilliseconds(1 + ((attempt % 12) * 3)));

                                    try
                                    {
                                        byte[] unexpected = await share.Files.ReadAllBytesAsync("large.bin", cancellationTokenSource.Token).ConfigureAwait(false);
                                        TestAssertions.SequenceEqual(large, unexpected, "Expected an uncancelled large read to return the full payload.");
                                    }
                                    catch (OperationCanceledException) when (!token.IsCancellationRequested)
                                    {
                                        cancelledCount++;
                                    }

                                    byte[] followUp = await share.Files.ReadAllBytesAsync("small.bin", token).ConfigureAwait(false);
                                    TestAssertions.SequenceEqual(small, followUp, "Expected a follow-up read on the same session to return its own response after a cancelled read.");
                                    OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync("large.bin", token).ConfigureAwait(false);
                                    TestAssertions.Equal((ulong)large.Length, metadata.EndOfFile, "Expected follow-up metadata on the same session to stay correlated after a cancelled read.");
                                    await client.EchoAsync(token).ConfigureAwait(false);
                                }

                                TestAssertions.True(cancelledCount > 0, "Expected at least one large read to be cancelled mid-flight.");
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryEncodesShareRootCreatesAndZeroLengthWritesWithMinimumVariableBuffer",
                        displayName: "Client primary encodes share-root creates and zero-length writes with the one-byte minimum variable buffer that Samba requires",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            Smb2CreateRequest rootCreate = new Smb2CreateRequest
                            {
                                Name = string.Empty,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.DirectoryFile
                            };
                            byte[] rootCreateBytes = rootCreate.ToByteArray();
                            TestAssertions.Equal(57, rootCreateBytes.Length, "Expected an empty-name create body to carry the 56-byte fixed part plus a one-byte buffer.");
                            TestAssertions.Equal((ushort)0x78, BitConverter.ToUInt16(rootCreateBytes, 44), "Expected an empty-name create to point NameOffset at the variable buffer.");
                            TestAssertions.Equal(string.Empty, Smb2CreateRequest.ReadFrom(rootCreateBytes).Name, "Expected the padded empty-name create to round-trip.");

                            Smb2WriteRequest emptyWrite = new Smb2WriteRequest { DataBuffer = Array.Empty<byte>() };
                            byte[] emptyWriteBytes = emptyWrite.ToByteArray();
                            TestAssertions.Equal(49, emptyWriteBytes.Length, "Expected a zero-length write body to carry the 48-byte fixed part plus a one-byte buffer.");
                            TestAssertions.Equal(0, Smb2WriteRequest.ReadFrom(emptyWriteBytes).DataBuffer.Length, "Expected the padded zero-length write to round-trip as empty.");

                            Smb2WriteRequest dataWrite = new Smb2WriteRequest { DataBuffer = new byte[] { 1, 2, 3 } };
                            TestAssertions.Equal(51, dataWrite.ToByteArray().Length, "Expected non-empty writes to carry no extra padding.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ClientPrimaryConcurrentOperationsOnOneShareSessionRemainCorrelated",
                        displayName: "Client primary concurrent read, write, metadata, and enumerate operations on one share session remain correlated",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsPrimaryConcurrency_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                await share.Directories.CreateAsync("stress", token).ConfigureAwait(false);
                                const int Workers = 32;
                                const int Iterations = 6;
                                Task[] tasks = new Task[Workers];

                                for (int worker = 0; worker < Workers; worker++)
                                {
                                    int workerIndex = worker;
                                    tasks[worker] = Task.Run(async () =>
                                    {
                                        for (int iteration = 0; iteration < Iterations; iteration++)
                                        {
                                            string path = "stress\\worker-" + workerIndex.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".bin";
                                            int length = 1000 + (workerIndex * 4099) + (iteration * 70001);
                                            byte[] payload = CreatePatternBytes(length, seed: (workerIndex * 17) + iteration);
                                            await share.Files.WriteAllBytesAsync(path, payload, token).ConfigureAwait(false);
                                            byte[] readBack = await share.Files.ReadAllBytesAsync(path, token).ConfigureAwait(false);
                                            TestAssertions.SequenceEqual(payload, readBack, "Expected concurrent read-back to return this worker's own payload.");
                                            OpenCifsClientFileMetadata metadata = await share.Metadata.GetAttributesAsync(path, token).ConfigureAwait(false);
                                            TestAssertions.Equal((ulong)length, metadata.EndOfFile, "Expected concurrent metadata to describe this worker's own file.");
                                            OpenCifsClientDirectoryEntry[] entries = await share.Directories.EnumerateAsync("stress", "worker-" + workerIndex.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".bin", token).ConfigureAwait(false);
                                            TestAssertions.Equal(1, entries.Length, "Expected concurrent filtered enumeration to return this worker's own entry.");
                                            TestAssertions.Equal((ulong)length, entries[0].EndOfFile, "Expected concurrent enumeration to report this worker's own size.");
                                        }
                                    }, token);
                                }

                                await Task.WhenAll(tasks).ConfigureAwait(false);
                                OpenCifsClientDirectoryEntry[] finalEntries = await share.Directories.EnumerateAsync("stress", cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal(Workers, finalEntries.Length, "Expected every concurrent worker file to exist after the stress run.");
                                await client.EchoAsync(token).ConfigureAwait(false);
                            })),
                });
        }
    }
}
