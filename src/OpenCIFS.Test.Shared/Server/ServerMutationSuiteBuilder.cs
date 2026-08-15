namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Sample.OpenCifsServer;
    using Touchstone.Core;
    using static OpenCIFS.Server.Tests.Shared.ServerTestSupport;
    internal static class ServerMutationSuiteBuilder
    {
        internal static TestSuiteDescriptor ServerMutationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Mutation",
                displayName: "Server malformed-input mutation smoke",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Mutation",
                        caseId: "ServerNegotiatesBaselineDirectTcpCorpusBeforeMutation",
                        displayName: "Server negotiates the baseline direct-TCP corpus before mutation",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                foreach (DirectTcpMutationRequestBaseline baseline in BuildDirectTcpMutationRequestBaselines())
                                {
                                    await AssertNegotiatesDirectTcpRequestAsync(port, baseline.Payload, token).ConfigureAwait(false);
                                }
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Mutation",
                        caseId: "ServerSurvivesMalformedDirectTcpMutationBurstAndOnlySurfacesProtocolExceptions",
                        displayName: "Server survives a malformed direct-TCP mutation burst and only surfaces bounded protocol exceptions",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            List<Exception> capturedExceptions = new List<Exception>();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                port,
                                exception =>
                                {
                                    lock (capturedExceptions)
                                    {
                                        capturedExceptions.Add(exception);
                                    }
                                },
                                token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            int totalMutations = 0;
                            string traceRootPath = TestPathUtilities.CreateUniqueDirectory("OpenCifsMutationTrace_");
                            PacketCaptureTraceWriter traceWriter = new PacketCaptureTraceWriter(traceRootPath, "ServerDirectTcpMutationBurst");

                            try
                            {
                                foreach (DirectTcpMutationRequestBaseline baseline in BuildDirectTcpMutationRequestBaselines())
                                {
                                    traceWriter.Capture(baseline.Name + "-baseline", baseline.Payload);
                                    IReadOnlyList<byte[]> mutations = MutationTestUtilities.CreateDeterministicMutationCorpus(
                                        baseline.Payload,
                                        randomSeed: 0x53525652 ^ DeterministicTestHash.ComputeInt32(baseline.Name),
                                        randomCount: 32);

                                    if (mutations.Count > 0)
                                    {
                                        traceWriter.Capture(baseline.Name + "-mutation-000", mutations[0]);
                                    }

                                    for (int index = 0; index < mutations.Count; index++)
                                    {
                                        await SendMalformedDirectTcpFrameAsync(port, mutations[index], token).ConfigureAwait(false);
                                    }

                                    totalMutations += mutations.Count;
                                }

                                byte[] recoveryPayload = BuildDirectTcpMutationRequestBaselines()[0].Payload;
                                traceWriter.Capture("recovery-negotiate", recoveryPayload);
                                FileAssertions.AssertExists(traceWriter.WriteManifest());
                                await AssertNegotiatesDirectTcpRequestAsync(port, recoveryPayload, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                                TestPathUtilities.DeleteDirectoryForcefully(traceRootPath);
                            }

                            TestAssertions.True(totalMutations >= 100, "Expected the server malformed-input mutation burst to execute at least 100 mutated direct-TCP requests.");

                            lock (capturedExceptions)
                            {
                                TestAssertions.True(capturedExceptions.Count > 0, "Expected the malformed direct-TCP mutation burst to surface at least one protocol exception.");

                                for (int index = 0; index < capturedExceptions.Count; index++)
                                {
                                    Exception exception = capturedExceptions[index];
                                    bool expected = exception is ProtocolEncodingException || exception is ProtocolValidationException;
                                    TestAssertions.True(
                                        expected,
                                        "Expected only bounded protocol exceptions from malformed direct-TCP traffic but observed " + exception.GetType().FullName + ".");
                                }
                            }
                        })
                });
        }
    }
}
