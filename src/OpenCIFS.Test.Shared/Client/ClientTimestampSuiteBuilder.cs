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
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientPrimaryDataTestSupport;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;

    /// <summary>
    /// Timestamp consistency coverage for the managed server as observed through the primary client surface.
    /// </summary>
    internal static class ClientTimestampSuiteBuilder
    {
        private const string SuiteId = "Client.Timestamps";

        /// <summary>
        /// Build the timestamp suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientTimestampSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: SuiteId,
                displayName: "Server timestamps advance on overwrite and stay stable and consistent across queries and connections",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ServerOverwriteAdvancesLastWriteTimeAndPreservesCreationTimeOnEveryWritePath",
                        displayName: "Server overwrite advances LastWriteTime, preserves CreationTime, and reports stable values on every client write path",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsTimestamps_",
                            token,
                            async (client, share, sharePath) =>
                            {
                                await share.Directories.CreateAsync("p", token).ConfigureAwait(false);
                                string localPath = Path.Combine(sharePath, "p", "times.txt");
                                await share.Files.WriteAllBytesAsync("p/times.txt", new byte[] { 1 }, token).ConfigureAwait(false);
                                OpenCifsClientFileMetadata initial = await share.Metadata.GetAttributesAsync("p/times.txt", token).ConfigureAwait(false);
                                DateTime creation = initial.CreationTimeUtc!.Value;
                                DateTime previousWrite = initial.LastWriteTimeUtc!.Value;
                                Func<Task>[] writers = new Func<Task>[]
                                {
                                    () => share.Files.WriteAllBytesAsync("p/times.txt", new byte[] { 2, 3 }, token),
                                    () => share.Files.WriteAllBytesAsync("p/times.txt", CreatePatternBytes((3 * 1024 * 1024) + 11), token),
                                    async () =>
                                    {
                                        using MemoryStream source = new MemoryStream(CreatePatternBytes(70000, seed: 3));
                                        await share.Files.WriteAsync("p/times.txt", source, cancellationToken: token).ConfigureAwait(false);
                                    },
                                    () => share.Files.WriteAllBytesAsync("p/times.txt", Array.Empty<byte>(), token),
                                };

                                for (int round = 0; round < 3; round++)
                                {
                                    for (int index = 0; index < writers.Length; index++)
                                    {
                                        await Task.Delay(30, token).ConfigureAwait(false);
                                        await writers[index]().ConfigureAwait(false);
                                        OpenCifsClientFileMetadata first = await share.Metadata.GetAttributesAsync("p/times.txt", token).ConfigureAwait(false);
                                        OpenCifsClientFileMetadata second = await share.Metadata.GetAttributesAsync("p/times.txt", token).ConfigureAwait(false);
                                        OpenCifsClientDirectoryEntry entry = (await share.Directories.EnumerateAsync("p", "times.txt", token).ConfigureAwait(false))[0];
                                        string label = "write path " + index + " round " + round;

                                        TestAssertions.True(first.LastWriteTimeUtc!.Value > previousWrite, "Expected LastWriteTime to advance after an overwrite (" + label + ").");
                                        TestAssertions.Equal(first.LastWriteTimeUtc!.Value.Ticks, second.LastWriteTimeUtc!.Value.Ticks, "Expected repeated queries of an unchanged file to return identical LastWriteTime (" + label + ").");
                                        TestAssertions.Equal(first.ChangeTimeUtc, second.ChangeTimeUtc, "Expected repeated queries of an unchanged file to return identical ChangeTime (" + label + ").");
                                        TestAssertions.Equal(first.LastWriteTimeUtc, entry.LastWriteTimeUtc, "Expected enumeration and metadata to agree on LastWriteTime (" + label + ").");
                                        TestAssertions.Equal(creation, first.CreationTimeUtc!.Value, "Expected an overwrite to preserve CreationTime (" + label + ").");
                                        TestAssertions.Equal(first.LastWriteTimeUtc!.Value.Ticks, File.GetLastWriteTimeUtc(localPath).Ticks, "Expected the reported LastWriteTime to match the backing file after the handle closed (" + label + ").");
                                        previousWrite = first.LastWriteTimeUtc.Value;
                                    }
                                }
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ServerDoesNotReturnStaleTimestampsToOtherConnections",
                        displayName: "Server does not return stale timestamps to a second connection after another connection overwrites the file",
                        executeAsync: token => RunWithPrimaryShareAsync(
                            "OpenCifsTimestampsCrossConnection_",
                            token,
                            async (writerClient, writer, sharePath) =>
                            {
                                await using OpenCifsClient readerClient = new OpenCifsClientBuilder()
                                    .WithServer(writerClient.Settings.ServerName, writerClient.Settings.ServerPort)
                                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                                    .Build();
                                await readerClient.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                                await using OpenCifsShareSession reader = await readerClient.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);

                                await writer.Files.WriteAllBytesAsync("shared.txt", new byte[] { 1 }, token).ConfigureAwait(false);
                                OpenCifsClientFileMetadata writerView = await writer.Metadata.GetAttributesAsync("shared.txt", token).ConfigureAwait(false);
                                OpenCifsClientFileMetadata readerView = await reader.Metadata.GetAttributesAsync("shared.txt", token).ConfigureAwait(false);
                                TestAssertions.Equal(writerView.LastWriteTimeUtc!.Value.Ticks, readerView.LastWriteTimeUtc!.Value.Ticks, "Expected both connections to report the same LastWriteTime.");
                                TestAssertions.Equal(writerView.CreationTimeUtc, readerView.CreationTimeUtc, "Expected both connections to report the same CreationTime.");

                                for (int round = 0; round < 5; round++)
                                {
                                    await Task.Delay(30, token).ConfigureAwait(false);
                                    await writer.Files.WriteAllBytesAsync("shared.txt", CreatePatternBytes(10 + round), token).ConfigureAwait(false);
                                    OpenCifsClientFileMetadata afterWriter = await writer.Metadata.GetAttributesAsync("shared.txt", token).ConfigureAwait(false);
                                    OpenCifsClientFileMetadata afterReader = await reader.Metadata.GetAttributesAsync("shared.txt", token).ConfigureAwait(false);
                                    TestAssertions.True(afterReader.LastWriteTimeUtc!.Value > readerView.LastWriteTimeUtc!.Value, "Expected the second connection to observe the advanced LastWriteTime instead of a cached value.");
                                    TestAssertions.Equal(afterWriter.LastWriteTimeUtc!.Value.Ticks, afterReader.LastWriteTimeUtc!.Value.Ticks, "Expected both connections to agree on LastWriteTime after an overwrite.");
                                    TestAssertions.Equal(writerView.CreationTimeUtc, afterReader.CreationTimeUtc, "Expected CreationTime to stay unchanged across overwrites.");
                                    readerView = afterReader;
                                }
                            })),
                    new TestCaseDescriptor(
                        suiteId: SuiteId,
                        caseId: "ServerReportsIdenticalTimestampsAfterRestartForUnchangedFiles",
                        displayName: "Server reports identical timestamps after a restart for files that were not changed in between",
                        executeAsync: async token =>
                        {
                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsTimestampsRestart_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsClientFileMetadata before = await WithServerAsync(sharePath, token, async share =>
                                {
                                    await share.Files.WriteAllBytesAsync("stable.txt", new byte[] { 1 }, token).ConfigureAwait(false);
                                    await Task.Delay(30, token).ConfigureAwait(false);
                                    await share.Files.WriteAllBytesAsync("stable.txt", new byte[] { 2, 3 }, token).ConfigureAwait(false);
                                    return await share.Metadata.GetAttributesAsync("stable.txt", token).ConfigureAwait(false);
                                }).ConfigureAwait(false);
                                OpenCifsClientFileMetadata after = await WithServerAsync(sharePath, token, share => share.Metadata.GetAttributesAsync("stable.txt", token)).ConfigureAwait(false);

                                TestAssertions.Equal(before.LastWriteTimeUtc!.Value.Ticks, after.LastWriteTimeUtc!.Value.Ticks, "Expected LastWriteTime to be identical after a server restart.");
                                TestAssertions.Equal(before.CreationTimeUtc, after.CreationTimeUtc, "Expected CreationTime to be identical after a server restart.");
                            }
                            finally
                            {
                                try
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                                catch (IOException)
                                {
                                }
                            }
                        }),
                });
        }

        private static async Task<T> WithServerAsync<T>(string sharePath, CancellationToken token, Func<OpenCifsShareSession, Task<T>> body)
        {
            int port = AllocateTcpPort();
            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);

            try
            {
                await using OpenCifsClient client = new OpenCifsClientBuilder()
                    .WithServer("127.0.0.1", port)
                    .WithDialectRange(SmbDialect.Smb2002, SmbDialect.Smb21)
                    .Build();
                await client.ConnectAsync(CreateCredential(), token).ConfigureAwait(false);
                await using OpenCifsShareSession share = await client.OpenShareAsync(TestEnvironmentDefaults.DefaultShareName, token).ConfigureAwait(false);
                return await body(share).ConfigureAwait(false);
            }
            finally
            {
                await StopDirectTcpServerAsync(serverHandle.CancellationTokenSource, serverHandle.ServerTask).ConfigureAwait(false);
            }
        }
    }
}
