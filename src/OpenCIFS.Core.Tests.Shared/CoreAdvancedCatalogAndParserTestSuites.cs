namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class CoreAdvancedCatalogAndParserTestSuites
    {
        internal static TestSuiteDescriptor FsccCatalogSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.FSCC",
                displayName: "FSCC information class catalogs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.FSCC",
                        caseId: "KnownInformationClassesResolve",
                        displayName: "Known FSCC information classes resolve and unknown values miss",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            bool foundFileInfo = FsccInformationClassCatalog.TryGetFileInformationClassInfo(FileInformationClass.BasicInformation, out FsccInformationClassInfo? fileInfo);
                            TestAssertions.True(foundFileInfo, "Expected BasicInformation metadata to be present.");
                            TestAssertions.True(fileInfo != null, "Expected BasicInformation metadata to be non-null.");
                            TestAssertions.Equal("BasicInformation", fileInfo!.Name, "Unexpected BasicInformation metadata name.");
                            TestAssertions.True(fileInfo.RequiresFileHandle, "BasicInformation should require a file handle.");

                            bool foundFileSystemInfo = FsccInformationClassCatalog.TryGetFileSystemInformationClassInfo(FileSystemInformationClass.VolumeInformation, out FsccInformationClassInfo? fileSystemInfo);
                            TestAssertions.True(foundFileSystemInfo, "Expected VolumeInformation metadata to be present.");
                            TestAssertions.True(fileSystemInfo != null, "Expected VolumeInformation metadata to be non-null.");
                            TestAssertions.Equal("VolumeInformation", fileSystemInfo!.Name, "Unexpected VolumeInformation metadata name.");
                            TestAssertions.False(fileSystemInfo.RequiresFileHandle, "VolumeInformation should not require a file handle.");

                            bool foundUnknownFileInfo = FsccInformationClassCatalog.TryGetFileInformationClassInfo(unchecked((FileInformationClass)0xFFFF), out FsccInformationClassInfo? missingFileInfo);
                            TestAssertions.False(foundUnknownFileInfo, "Unexpected metadata was returned for an unknown file information class.");
                            TestAssertions.True(missingFileInfo == null, "Unknown file information classes should not return metadata.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.FSCC",
                        caseId: "UnknownInformationClassesRejectResolution",
                        displayName: "Unknown FSCC information classes reject resolution",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            bool foundUnknownFileInfo = FsccInformationClassCatalog.TryGetFileInformationClassInfo(unchecked((FileInformationClass)0x7FFF), out FsccInformationClassInfo? missingFileInfo);
                            TestAssertions.False(foundUnknownFileInfo, "Unexpected file-information metadata was returned for an unknown FSCC information class.");
                            TestAssertions.True(missingFileInfo == null, "Unknown file-information classes should not return metadata.");

                            bool foundUnknownFileSystemInfo = FsccInformationClassCatalog.TryGetFileSystemInformationClassInfo(unchecked((FileSystemInformationClass)0x7FFF), out FsccInformationClassInfo? missingFileSystemInfo);
                            TestAssertions.False(foundUnknownFileSystemInfo, "Unexpected filesystem metadata was returned for an unknown FSCC information class.");
                            TestAssertions.True(missingFileSystemInfo == null, "Unknown filesystem information classes should not return metadata.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the state lifecycle suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>

        internal static TestSuiteDescriptor StateLifecycleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.State",
                displayName: "Protocol state lifecycles",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "ConnectionAndCreditStatesFollowLifecycle",
                        displayName: "Connection and credit states follow lifecycle rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            ConnectionState connection = new ConnectionState();
                            TestAssertions.False(connection.IsNegotiated, "A new connection should not be negotiated.");

                            connection.Credits.Grant(5);
                            connection.Credits.Consume(2);
                            connection.Credits.Return(1);
                            TestAssertions.Equal(4, connection.Credits.AvailableCredits, "Unexpected credit count.");

                            connection.Negotiate(SmbDialect.Smb311);
                            TestAssertions.True(connection.IsNegotiated, "The connection should be marked negotiated.");
                            TestAssertions.Equal(SmbDialect.Smb311, connection.NegotiatedDialect!.Value, "Unexpected negotiated dialect.");

                            connection.Dispose();
                            TestAssertions.True(connection.IsDisposed, "The connection should report that it has been disposed.");
                            TestAssertions.True(connection.Credits.IsDisposed, "Disposing the connection should dispose the credit state.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => connection.Negotiate(SmbDialect.Smb30),
                                "Using a disposed connection should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "SessionTreeAndOpenStatesFollowLifecycle",
                        displayName: "Session, tree, and open states follow lifecycle rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SessionState session = new SessionState();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.Authenticate(),
                                "Authenticating before binding a session identifier should fail.");
                            session.Bind(0x0102030405060708UL);
                            session.Authenticate();
                            TestAssertions.True(session.IsAuthenticated, "The session should be authenticated.");

                            TreeConnectState tree = new TreeConnectState();
                            tree.Connect(0xABCD1234U, "share");
                            TestAssertions.True(tree.IsConnected, "The tree should be connected.");
                            TestAssertions.Equal("share", tree.ShareName, "Unexpected share name.");
                            tree.Disconnect();
                            TestAssertions.False(tree.IsConnected, "The tree should be disconnected.");

                            OpenState open = new OpenState();
                            TestAssertions.Throws<ArgumentException>(
                                () => open.Bind(0, 0, "file.txt"),
                                "Binding an open with zero file identifiers should fail.");
                            open.Bind(1, 2, "folder\\file.txt");
                            open.MarkDeletePending();
                            TestAssertions.True(open.IsDeletePending, "The open should be delete-pending.");
                            TestAssertions.Equal("folder\\file.txt", open.Path, "Unexpected open path.");

                            session.Dispose();
                            tree.Dispose();
                            open.Dispose();

                            TestAssertions.Throws<ObjectDisposedException>(
                                () => session.Bind(1),
                                "Using a disposed session should fail.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => tree.Connect(1, "share"),
                                "Using a disposed tree should fail.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => open.MarkDeletePending(),
                                "Using a disposed open should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "RequestAndCompoundStatesFollowLifecycle",
                        displayName: "Request and compound states follow lifecycle rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            RequestState request = new RequestState();
                            request.Bind(42, Smb2Command.Read);
                            request.Complete();
                            TestAssertions.Equal(42UL, request.MessageId, "Unexpected request message identifier.");
                            TestAssertions.Equal(Smb2Command.Read, request.Command, "Unexpected request command.");
                            TestAssertions.True(request.IsCompleted, "The request should be completed.");

                            CompoundChainState compound = new CompoundChainState();
                            compound.Append(Smb2Command.Create);
                            compound.Append(Smb2Command.Close);
                            compound.Seal();
                            TestAssertions.Equal(2, compound.Commands.Count, "Unexpected compound command count.");
                            TestAssertions.Equal(Smb2Command.Create, compound.Commands[0], "Unexpected first compound command.");
                            TestAssertions.Equal(Smb2Command.Close, compound.Commands[1], "Unexpected second compound command.");
                            TestAssertions.True(compound.IsSealed, "The compound chain should be sealed.");
                            TestAssertions.Throws<InvalidOperationException>(
                                () => compound.Append(Smb2Command.Read),
                                "Appending to a sealed compound chain should fail.");

                            request.Dispose();
                            compound.Dispose();
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => request.Complete(),
                                "Using a disposed request should fail.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => compound.Seal(),
                                "Using a disposed compound chain should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "StateObjectsRejectInvalidTransitionsAndDisposedReuse",
                        displayName: "State objects reject invalid transitions and disposed reuse",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            CreditState credits = new CreditState();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => credits.Consume(1),
                                "Credit state should reject consuming credits before any have been granted.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => credits.Grant(0),
                                "Credit state should reject non-positive grants.");

                            SessionState session = new SessionState();
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => session.Bind(0),
                                "Session state should reject zero-valued session identifiers.");

                            CompoundChainState compound = new CompoundChainState();
                            compound.Seal();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => compound.Append(Smb2Command.Read),
                                "Compound state should reject appends after the chain is sealed.");

                            RequestState request = new RequestState();
                            request.Dispose();
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => request.MarkAsync(1),
                                "Disposed request state should reject async assignment.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the bounded deterministic parser-mutation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>

        internal static TestSuiteDescriptor ParserMutationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Mutation",
                displayName: "Deterministic parser mutation smoke",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Mutation",
                        caseId: "BaselineProtocolCorpusParsesBeforeMutation",
                        displayName: "Baseline protocol corpus parses before mutation",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            foreach (ProtocolMutationCorpusEntry corpusEntry in BuildProtocolMutationCorpus())
                            {
                                corpusEntry.Parser(corpusEntry.Baseline);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Mutation",
                        caseId: "DeterministicProtocolMutationsRejectOrContainMalformedInputs",
                        displayName: "Deterministic protocol mutations reject or contain malformed inputs without unexpected parser failures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int totalMutations = 0;
                            int totalAccepted = 0;
                            int totalRejected = 0;

                            foreach (ProtocolMutationCorpusEntry corpusEntry in BuildProtocolMutationCorpus())
                            {
                                IReadOnlyList<byte[]> mutations = MutationTestUtilities.CreateDeterministicMutationCorpus(
                                    corpusEntry.Baseline,
                                    randomSeed: 0x43494653 ^ DeterministicTestHash.ComputeInt32(corpusEntry.Name),
                                    randomCount: 48);
                                MutationOutcomeSummary summary = MutationTestUtilities.ExecuteMutationCorpus(
                                    corpusEntry.Name,
                                    mutations,
                                    corpusEntry.Parser,
                                    MutationTestUtilities.IsExpectedMalformedInputException);

                                TestAssertions.True(summary.RejectedCount > 0, "Expected mutation corpus '" + corpusEntry.Name + "' to reject at least one malformed payload.");
                                totalMutations += summary.TotalCount;
                                totalAccepted += summary.AcceptedCount;
                                totalRejected += summary.RejectedCount;
                            }

                            TestAssertions.True(totalMutations >= 1500, "Expected the deterministic parser-mutation corpus to execute at least 1500 mutated payloads across the broader SMB1, SMB2/3, DFS, and NetBIOS coverage.");
                            TestAssertions.True(totalRejected >= 600, "Expected the deterministic parser-mutation corpus to reject a meaningful number of malformed payloads.");
                            TestAssertions.True(totalAccepted > 0, "Expected at least one deterministic mutation to remain structurally parseable.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Mutation",
                        caseId: "ReplayAttemptHelpersBuildAndPreserveSignedRequestBytesAndRejectInvalidInputs",
                        displayName: "Replay-attempt helpers build and preserve signed-request bytes and reject invalid inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] capturedSignedRequest = new byte[]
                            {
                                0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                                0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
                            };

                            byte[] firstReplay = ReplayAttemptUtilities.CreateReplayCopy(capturedSignedRequest);
                            byte[] secondReplay = ReplayAttemptUtilities.CreateReplayCopy(capturedSignedRequest);
                            TestAssertions.SequenceEqual(capturedSignedRequest, firstReplay, "Replay copies should preserve the captured signed-request bytes.");
                            TestAssertions.SequenceEqual(firstReplay, secondReplay, "Repeated replay copies should be deterministic.");

                            firstReplay[0] = 0x00;
                            TestAssertions.True(capturedSignedRequest[0] == 0xFE, "Mutating a replay copy should not affect the captured signed-request bytes.");

                            IReadOnlyList<byte[]> replayBurst = ReplayAttemptUtilities.CreateReplayBurst(capturedSignedRequest, replayCount: 4);
                            TestAssertions.Equal(4, replayBurst.Count, "Unexpected replay-burst count.");

                            for (int index = 0; index < replayBurst.Count; index++)
                            {
                                TestAssertions.SequenceEqual(capturedSignedRequest, replayBurst[index], "Each replay-burst entry should match the captured signed request.");
                            }

                            TestAssertions.Throws<ArgumentNullException>(
                                () => ReplayAttemptUtilities.CreateReplayCopy(null!),
                                "Replay-copy helpers should reject null input.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => ReplayAttemptUtilities.CreateReplayBurst(capturedSignedRequest, replayCount: 0),
                                "Replay-burst helpers should reject non-positive counts.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
