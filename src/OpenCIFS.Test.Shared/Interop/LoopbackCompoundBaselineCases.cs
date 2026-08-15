namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class LoopbackCompoundBaselineCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerCompleteUnrelatedCompoundFileIoChain",
                        displayName: "Client and server loopback complete an unrelated compounded write, flush, read, and close chain",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 8);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "compound.txt"));
                                OpenState openState = client.ApplyCreateResult(treeId, "compound.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("compound data");
                                Smb2Header writeHeader = client.CreateRequestHeader(Smb2Command.Write, treeId, sessionId: client.SessionId.Value);
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                Smb2Header flushHeader = client.CreateRequestHeader(Smb2Command.Flush, treeId, sessionId: client.SessionId.Value);
                                Smb2FlushRequest flushRequest = client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId);
                                Smb2Header readHeader = client.CreateRequestHeader(Smb2Command.Read, treeId, sessionId: client.SessionId.Value);
                                Smb2ReadRequest readRequest = client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, (uint)payload.Length, 0, minimumCount: (uint)payload.Length);
                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: client.SessionId.Value);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(writeHeader, writeRequest.ToByteArray()),
                                        new Smb2CompoundPacketEntry(flushHeader, flushRequest.ToByteArray()),
                                        new Smb2CompoundPacketEntry(readHeader, readRequest.ToByteArray()),
                                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                                    });
                                Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());

                                client.ApplyCompoundResponsePacket(parsedResponsePacket);

                                Smb2WriteResponse writeResponse = Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload));
                                Smb2FlushResponse flushResponse = Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[1].Header.Command, parsedResponsePacket.Entries[1].Payload));
                                Smb2ReadResponse readResponse = Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[2].Header.Command, parsedResponsePacket.Entries[2].Payload));
                                Smb2CloseResponse closeResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[3].Header.Command, parsedResponsePacket.Entries[3].Payload));

                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[0].Header.Status, writeResponse), "Unexpected compounded loopback write count.");
                                client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[1].Header.Status, flushResponse);
                                byte[] readBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[2].Header.Status, readResponse);
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[3].Header.Status, closeResponse);

                                TestAssertions.True(parsedResponsePacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded response to point at a subsequent response.");
                                TestAssertions.SequenceEqual(payload, readBytes, "Unexpected bytes returned by the compounded loopback read path.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the compounded close response to clear the loopback open.");
                                TestAssertions.Equal(0, client.PendingRequestCount, "Expected every compounded loopback request to complete.");
                                TestAssertions.Equal(8, client.AvailableCredits, "Expected the loopback client to restore the negotiated credit window after the compounded response.");
                                TestAssertions.Equal(8, server.AvailableCredits, "Expected the loopback server to restore the negotiated credit window after the compounded response.");
                                TestAssertions.SequenceEqual(payload, File.ReadAllBytes(Path.Combine(sharePath, "compound.txt")), "Unexpected bytes persisted by the compounded loopback file-I/O path.");
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
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerCompleteRelatedCompoundTreeMetadataLockIoctlAndCloseChain",
                        displayName: "Client and server loopback complete a related compounded tree-connect, create, set-info, query-info, lock, IOCTL, close, and tree-disconnect chain",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropRelatedCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 9);

                                Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
                                Smb2Header createHeader = client.CreateRelatedRequestHeader(Smb2Command.Create, sessionId: sessionId);
                                Smb2Header setInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.SetInfo, sessionId: sessionId);
                                Smb2Header queryInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: sessionId);
                                Smb2Header lockHeader = client.CreateRelatedRequestHeader(Smb2Command.Lock, sessionId: sessionId);
                                Smb2Header unlockHeader = client.CreateRelatedRequestHeader(Smb2Command.Lock, sessionId: sessionId);
                                Smb2Header ioctlHeader = client.CreateRelatedRequestHeader(Smb2Command.Ioctl, sessionId: sessionId);
                                Smb2Header closeHeader = client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: sessionId);
                                Smb2Header treeDisconnectHeader = client.CreateRelatedRequestHeader(Smb2Command.TreeDisconnect, sessionId: sessionId);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            treeConnectHeader,
                                            client.CreateTreeConnectRequest("public").ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            createHeader,
                                            new Smb2CreateRequest
                                            {
                                                RequestedOplockLevel = Smb2OplockLevel.None,
                                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                                DesiredAccess = 0xC0000000U,
                                                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                                ShareAccess = 0x00000007U,
                                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                                Name = "related.txt",
                                                CreateContexts = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            setInfoHeader,
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
                                            queryInfoHeader,
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
                                            lockHeader,
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
                                            unlockHeader,
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
                                            ioctlHeader,
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
                                            closeHeader,
                                            new Smb2CloseRequest
                                            {
                                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            treeDisconnectHeader,
                                            new Smb2TreeDisconnectRequest().ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedResponsePacket);

                                Smb2TreeConnectResponse treeConnectResponse = Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload));
                                Smb2CreateResponse createResponse = Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[1].Header.Command, parsedResponsePacket.Entries[1].Payload));
                                Smb2SetInfoResponse setInfoResponse = Smb2SetInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[2].Header.Command, parsedResponsePacket.Entries[2].Payload));
                                Smb2QueryInfoResponse queryInfoResponse = Smb2QueryInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[3].Header.Command, parsedResponsePacket.Entries[3].Payload));
                                Smb2LockResponse lockResponse = Smb2LockResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[4].Header.Command, parsedResponsePacket.Entries[4].Payload));
                                Smb2LockResponse unlockResponse = Smb2LockResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[5].Header.Command, parsedResponsePacket.Entries[5].Payload));
                                Smb2IoctlResponse ioctlResponse = Smb2IoctlResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[6].Header.Command, parsedResponsePacket.Entries[6].Payload));
                                Smb2CloseResponse closeResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[7].Header.Command, parsedResponsePacket.Entries[7].Payload));
                                Smb2TreeDisconnectResponse treeDisconnectResponse = Smb2TreeDisconnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[8].Header.Command, parsedResponsePacket.Entries[8].Payload));

                                client.ApplyTreeConnectResult("public", parsedResponsePacket.Entries[0].Header.TreeId, parsedResponsePacket.Entries[0].Header.Status, treeConnectResponse);
                                OpenState openState = client.ApplyCreateResult(parsedResponsePacket.Entries[0].Header.TreeId, "related.txt", parsedResponsePacket.Entries[1].Header.Status, createResponse);
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[2].Header.Status, setInfoResponse);
                                FileBasicInformation relatedBasicInformation = FileBasicInformation.ReadFrom(client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[3].Header.Status, queryInfoResponse));
                                client.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[4].Header.Status, lockResponse);
                                client.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[5].Header.Status, unlockResponse);
                                SrvSnapshotArray snapshotArray = client.ApplyEnumerateSnapshotsResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[6].Header.Status, ioctlResponse);
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, parsedResponsePacket.Entries[7].Header.Status, closeResponse);
                                client.ApplyTreeDisconnectResult(parsedResponsePacket.Entries[0].Header.TreeId, parsedResponsePacket.Entries[8].Header.Status, treeDisconnectResponse);

                                TestAssertions.True((relatedBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected related compounded loopback FILE_BASIC_INFORMATION queries to include Hidden.");
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected related compounded loopback snapshot enumeration to expose no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected related compounded loopback snapshot enumeration to return an empty list.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations | Smb2HeaderFlags.Signed, parsedResponsePacket.Entries[1].Header.Flags, "Expected related compounded loopback responses to preserve signing and mark subsequent entries as related operations.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the related compounded close response to clear the loopback open.");
                                TestAssertions.Equal(0, client.ConnectedTreeIds.Length, "Expected the related compounded tree-disconnect response to clear the connected tree.");
                                TestAssertions.Equal(9, client.AvailableCredits, "Expected the related compounded loopback response to restore the negotiated client credit window.");
                                TestAssertions.Equal(9, server.AvailableCredits, "Expected the related compounded loopback response to restore the negotiated server credit window.");
                                TestAssertions.True((File.GetAttributes(Path.Combine(sharePath, "related.txt")) & System.IO.FileAttributes.Hidden) != 0, "Expected the related compounded loopback set-info request to persist the Hidden attribute.");
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
            };
        }
    }
}
