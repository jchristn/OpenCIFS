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
    internal static class LoopbackFileIoLifecycleCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerCompleteFileIoLifecycle",
                        displayName: "Client and server loopback complete create, write, flush, read, and close against a temp share",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "loopback.txt");
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "loopback.txt", createResult.Status, createResult.Response);
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the created loopback open.");

                                byte[] payload = Encoding.UTF8.GetBytes("loopback data");
                                Smb2WriteRequest writeRequest = client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0);
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(client.SessionId!.Value, treeId, writeRequest);
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected loopback write count.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = server.HandleFlush(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, flushResult.Status, flushResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, (uint)payload.Length, 0, minimumCount: (uint)payload.Length));
                                byte[] readBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, readResult.Status, readResult.Response);
                                TestAssertions.SequenceEqual(payload, readBytes, "Unexpected loopback read payload.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback open after close.");

                                byte[] storedBytes = File.ReadAllBytes(Path.Combine(sharePath, "loopback.txt"));
                                TestAssertions.SequenceEqual(payload, storedBytes, "Unexpected bytes persisted by the loopback file-I/O path.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerCompleteEncryptedFileIoLifecycleUnderSmb302",
                        displayName: "Client and server loopback complete encrypted create, write, flush, read, and close under SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropEncryptedFileIo_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath, maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: true);
                                OpenCifsClientSession client = CreateNegotiatedClient(server, maximumDialect: SmbDialect.Smb302, preferEncryption: true);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateEncryptedLoopbackSessionAndTree(server, client, credential);

                                Smb2CompoundPacket createResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value),
                                            client.CreateCreateRequest(treeId, "encrypted-loopback.txt").ToByteArray())
                                    }),
                                    "encrypted create");
                                OpenState openState = client.ApplyCreateResult(
                                    treeId,
                                    "encrypted-loopback.txt",
                                    createResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(createResponsePacket.Entries[0].Header.Command, createResponsePacket.Entries[0].Payload)));
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the encrypted loopback open.");

                                byte[] payload = Encoding.UTF8.GetBytes("encrypted loopback data");
                                Smb2CompoundPacket writeResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Write, treeId, sessionId: client.SessionId.Value),
                                            client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0).ToByteArray())
                                    }),
                                    "encrypted write");
                                TestAssertions.Equal(
                                    (uint)payload.Length,
                                    client.ApplyWriteResult(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        writeResponsePacket.Entries[0].Header.Status,
                                        Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(writeResponsePacket.Entries[0].Header.Command, writeResponsePacket.Entries[0].Payload))),
                                    "Unexpected encrypted loopback write count.");

                                Smb2CompoundPacket flushResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Flush, treeId, sessionId: client.SessionId.Value),
                                            client.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId).ToByteArray())
                                    }),
                                    "encrypted flush");
                                client.ApplyFlushResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    flushResponsePacket.Entries[0].Header.Status,
                                    Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(flushResponsePacket.Entries[0].Header.Command, flushResponsePacket.Entries[0].Payload)));

                                Smb2CompoundPacket readResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Read, treeId, sessionId: client.SessionId.Value),
                                            client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, (uint)payload.Length, 0, minimumCount: (uint)payload.Length).ToByteArray())
                                    }),
                                    "encrypted read");
                                byte[] readBytes = client.ApplyReadResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    readResponsePacket.Entries[0].Header.Status,
                                    Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(readResponsePacket.Entries[0].Header.Command, readResponsePacket.Entries[0].Payload)));
                                TestAssertions.SequenceEqual(payload, readBytes, "Unexpected encrypted loopback read payload.");

                                Smb2CompoundPacket closeResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: client.SessionId.Value),
                                            client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true).ToByteArray())
                                    }),
                                    "encrypted close");
                                client.ApplyCloseResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    closeResponsePacket.Entries[0].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(closeResponsePacket.Entries[0].Header.Command, closeResponsePacket.Entries[0].Payload)));
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the encrypted loopback open after close.");

                                byte[] storedBytes = File.ReadAllBytes(Path.Combine(sharePath, "encrypted-loopback.txt"));
                                TestAssertions.SequenceEqual(payload, storedBytes, "Unexpected bytes persisted by the encrypted loopback file-I/O path.");
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
                        suiteId: "Interop.LoopbackFileIo",
                        caseId: "ClientAndServerReportEofAfterReadingPastData",
                        displayName: "Client and server loopback report EOF cleanly after reading past the written data",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "eof.txt"));
                                OpenState openState = client.ApplyCreateResult(treeId, "eof.txt", createResult.Status, createResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("abc");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> eofResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 3));
                                byte[] eofBytes = client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, eofResult.Status, eofResult.Response);
                                TestAssertions.Equal(0, eofBytes.Length, "Expected loopback EOF reads to return an empty payload.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
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

