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
    internal static class ServerCompoundingSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Compounding",
                displayName: "Server SMB2 compounding handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerHandlesUnrelatedCompoundWriteFlushClosePacket",
                        displayName: "Server handles an unrelated compounded write, flush, and close packet against an authenticated open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("compound.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the server to open a backing file before compounded I/O.");

                                byte[] payload = Encoding.UTF8.GetBytes("compound data");
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Write, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId),
                                            new Smb2WriteRequest
                                            {
                                                Offset = 0,
                                                PersistentFileId = createResult.Response.PersistentFileId,
                                                VolatileFileId = createResult.Response.VolatileFileId,
                                                Channel = 0,
                                                RemainingBytes = 0,
                                                Flags = Smb2WriteFlags.None,
                                                DataBuffer = payload,
                                                WriteChannelInfo = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Flush, messageId: 1, sessionId: sessionId, treeId: treeId),
                                            new Smb2FlushRequest
                                            {
                                                PersistentFileId = createResult.Response.PersistentFileId,
                                                VolatileFileId = createResult.Response.VolatileFileId
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Close, messageId: 2, sessionId: sessionId, treeId: treeId),
                                            new Smb2CloseRequest
                                            {
                                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                                PersistentFileId = createResult.Response.PersistentFileId,
                                                VolatileFileId = createResult.Response.VolatileFileId
                                            }.ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(3, responsePacket.Entries.Count, "Unexpected compounded response entry count.");
                                TestAssertions.True(responsePacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded response to point at the next response entry.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the compounded write response to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected the compounded flush response to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[2].Header.Status, "Expected the compounded close response to succeed.");

                                Smb2WriteResponse writeResponse = Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                                Smb2FlushResponse flushResponse = Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[1].Header.Command, responsePacket.Entries[1].Payload));
                                Smb2CloseResponse closeResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[2].Header.Command, responsePacket.Entries[2].Payload));

                                Smb2FlushResponseValidator.Validate(flushResponse);
                                Smb2CloseResponseValidator.Validate(closeResponse);
                                TestAssertions.Equal((uint)payload.Length, writeResponse.Count, "Unexpected compounded write-response byte count.");
                                TestAssertions.Equal((ulong)payload.Length, closeResponse.EndOfFile, "Unexpected compounded close-response EOF size.");
                                TestAssertions.SequenceEqual(payload, File.ReadAllBytes(Path.Combine(sharePath, "compound.txt")), "Unexpected bytes persisted by the compounded server packet path.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerHandlesUnrelatedCompoundEchoAndLogoffPacket",
                        displayName: "Server handles an unrelated compounded echo and logoff packet against an authenticated session",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 2, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Logoff, messageId: 1, sessionId: sessionId),
                                        new Smb2LogoffRequest().ToByteArray())
                                });

                            Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                            TestAssertions.Equal(2, responsePacket.Entries.Count, "Unexpected compounded echo/logoff response entry count.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected compounded echo to succeed.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected compounded logoff to succeed.");

                            Smb2EchoResponse echoResponse = Smb2EchoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                            Smb2LogoffResponse logoffResponse = Smb2LogoffResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[1].Header.Command, responsePacket.Entries[1].Payload));
                            Smb2EchoResponseValidator.Validate(echoResponse);
                            Smb2LogoffResponseValidator.Validate(logoffResponse);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerCarriesSessionIdAcrossUnrelatedSessionSetupAndTreeConnectPacket",
                        displayName: "Server carries the authenticated session id across an unrelated compounded session-setup and tree-connect packet",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the server to issue a session-setup challenge before compounded authentication.");

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.SessionSetup, messageId: 0, creditRequest: 2, sessionId: challengeResult.SessionId),
                                        CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult).ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.TreeConnect, messageId: 1, sessionId: 0),
                                        new Smb2TreeConnectRequest
                                        {
                                            Path = "\\\\LAB-SERVER\\public"
                                        }.ToByteArray())
                                });

                            Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                            TestAssertions.Equal(2, responsePacket.Entries.Count, "Unexpected compounded session-setup/tree-connect response entry count.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the compounded session-setup completion to succeed.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected the compounded tree connect to succeed.");
                            TestAssertions.Equal(challengeResult.SessionId, responsePacket.Entries[1].Header.SessionId, "Expected the compounded tree-connect response to use the authenticated session id.");

                            Smb2SessionSetupResponse sessionSetupResponse = Smb2SessionSetupResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                            Smb2TreeConnectResponse treeConnectResponse = Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[1].Header.Command, responsePacket.Entries[1].Payload));
                            Smb2SessionSetupResponseValidator.Validate(sessionSetupResponse);
                            Smb2TreeConnectResponseValidator.Validate(treeConnectResponse);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerHandlesRelatedCompoundTreeConnectCreateMetadataLockIoctlCloseAndDisconnectPacket",
                        displayName: "Server handles a related compounded tree-connect, create, set-info, query-info, lock, IOCTL, close, and tree-disconnect packet",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerRelatedCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                ulong sessionId = AuthenticateSession(host);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.TreeConnect, messageId: 0, creditRequest: 9, sessionId: sessionId),
                                            new Smb2TreeConnectRequest
                                            {
                                                Path = "\\\\LAB-SERVER\\public"
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Create, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            CreateFileCreateRequest("related.txt", Smb2CreateDisposition.OpenIf).ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.SetInfo, messageId: 2, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.QueryInfo, messageId: 3, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Lock, messageId: 4, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Lock, messageId: 5, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.Unlock
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Ioctl, messageId: 6, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Close, messageId: 7, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2CloseRequest
                                            {
                                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.TreeDisconnect, messageId: 8, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2TreeDisconnectRequest().ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(9, responsePacket.Entries.Count, "Unexpected related compounded response entry count.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected related tree connect to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected related create to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[2].Header.Status, "Expected related set-info to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[3].Header.Status, "Expected related query-info to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[4].Header.Status, "Expected related lock to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[5].Header.Status, "Expected related unlock to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[6].Header.Status, "Expected related IOCTL to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[7].Header.Status, "Expected related close to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[8].Header.Status, "Expected related tree disconnect to succeed.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations, responsePacket.Entries[1].Header.Flags, "Expected subsequent related compounded responses to carry the related-operation flag.");

                                Smb2QueryInfoResponse queryInfoResponse = Smb2QueryInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[3].Header.Command, responsePacket.Entries[3].Payload));
                                FileBasicInformation relatedBasicInformation = FileBasicInformation.ReadFrom(queryInfoResponse.OutputBuffer);
                                TestAssertions.True((relatedBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected related compounded FILE_BASIC_INFORMATION query results to include Hidden.");

                                Smb2IoctlResponse ioctlResponse = Smb2IoctlResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[6].Header.Command, responsePacket.Entries[6].Payload));
                                SrvSnapshotArray snapshotArray = SrvSnapshotArray.ReadFrom(ioctlResponse.OutputBuffer);
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected related compounded snapshot enumeration to return no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected related compounded snapshot enumeration to return an empty list.");
                                TestAssertions.True((File.GetAttributes(Path.Combine(sharePath, "related.txt")) & System.IO.FileAttributes.Hidden) != 0, "Expected the related compounded set-info request to persist the Hidden attribute.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerRejectsRelatedCompoundChainsWithoutRequiredContext",
                        displayName: "Server rejects related compounded packets that begin outside the supported synchronous compound surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);

                            Smb2CompoundPacket missingTreePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 2, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Read, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                        new Smb2ReadRequest
                                        {
                                            Length = 1,
                                            Offset = 0,
                                            PersistentFileId = UInt64.MaxValue,
                                            VolatileFileId = UInt64.MaxValue,
                                            MinimumCount = 0,
                                            Channel = 0,
                                            RemainingBytes = 0,
                                            ReadChannelInfo = Array.Empty<byte>()
                                        }.ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(missingTreePacket.ToByteArray())),
                                "Expected related compounded packets that begin with commands outside the supported synchronous compound surface to be rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerPropagatesRelatedCreateFailureAcrossMetadataLockIoctlAndCloseOperations",
                        displayName: "Server propagates related compounded create failure statuses across later metadata, locking, IOCTL, and close operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerRelatedCompoundFailure_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "collision.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                ulong sessionId = AuthenticateSession(host);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.TreeConnect, messageId: 0, creditRequest: 7, sessionId: sessionId),
                                            new Smb2TreeConnectRequest
                                            {
                                                Path = "\\\\LAB-SERVER\\public"
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Create, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            CreateFileCreateRequest("collision.txt", Smb2CreateDisposition.Create).ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.SetInfo, messageId: 2, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.QueryInfo, messageId: 3, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Lock, messageId: 4, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Ioctl, messageId: 5, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Close, messageId: 6, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(7, responsePacket.Entries.Count, "Unexpected related compounded response count for the propagated-failure scenario.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the leading tree connect to succeed.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[1].Header.Status, "Expected the related create to report the collision.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[2].Header.Status, "Expected the related set-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[3].Header.Status, "Expected the related query-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[4].Header.Status, "Expected the related lock to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[5].Header.Status, "Expected the related IOCTL to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[6].Header.Status, "Expected the related close to inherit the create failure status.");
                                TestAssertions.Equal("seed", File.ReadAllText(Path.Combine(sharePath, "collision.txt")), "Expected propagated create failures to avoid mutating the backing file.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerRejectsMixedCompoundStyles",
                        displayName: "Server rejects compounded request packets that mix unrelated and related operation styles",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 0, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Logoff, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                        new Smb2LogoffRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 2, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleCompoundRequestPacket(requestPacket),
                                "Expected the server to reject compounded packets that mix unrelated and related SMB2 operation styles.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
