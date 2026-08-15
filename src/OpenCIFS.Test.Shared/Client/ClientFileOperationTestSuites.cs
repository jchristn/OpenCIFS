namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;
    internal static class ClientFileOperationTestSuites
    {
        /// <summary>
        /// Build the client SMB2 compounding suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientCompoundingSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Compounding",
                displayName: "Client SMB2 compounding handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientAppliesCompoundedResponsePacketHeaders",
                        displayName: "Client applies compounded response headers in wire order and releases pending requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            GrantCredits(session, 4);

                            Smb2Header firstPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2Header secondPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(firstPendingHeader), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(secondPendingHeader), Array.Empty<byte>())
                                });

                            session.ApplyCompoundResponsePacket(responsePacket);

                            TestAssertions.True(responsePacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded response header to point at the next entry.");
                            TestAssertions.Equal(4, session.AvailableCredits, "Expected compounded response headers to restore the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected compounded response headers to complete every pending request in the packet.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientAcceptsZeroCreditGrantsOnNonFinalCompoundedResponses",
                        displayName: "Client accepts zero credit grants on non-final compounded response headers when the final response restores credits",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            GrantCredits(session, 4);

                            Smb2Header firstPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2Header secondPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(firstPendingHeader, grantedCredits: 0), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(secondPendingHeader, grantedCredits: 2), Array.Empty<byte>())
                                });

                            session.ApplyCompoundResponsePacket(responsePacket);

                            TestAssertions.Equal(4, session.AvailableCredits, "Expected the final compounded response header to restore the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected zero-credit non-final compounded responses to still complete their pending requests.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientRejectsUnknownMessageInCompoundedResponsePacket",
                        displayName: "Client rejects a compounded response packet that includes an unknown SMB2 message identifier",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateNegotiatedClient();
                            GrantCredits(session, 4);

                            Smb2Header knownPendingHeader = session.CreateRequestHeader(Smb2Command.SessionSetup);
                            session.CreateRequestHeader(Smb2Command.SessionSetup);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(knownPendingHeader), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(
                                        new Smb2Header
                                        {
                                            CreditCharge = 0,
                                            Status = NtStatus.Success,
                                            Command = Smb2Command.SessionSetup,
                                            CreditRequest = 1,
                                            Flags = Smb2HeaderFlags.ServerToRedir,
                                            NextCommand = 0,
                                            MessageId = 99,
                                            Signature = new byte[16]
                                        },
                                        Array.Empty<byte>())
                                });

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyCompoundResponsePacket(responsePacket),
                                "Expected the client to reject compounded response headers that do not match a pending SMB2 message identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Compounding",
                        caseId: "ClientBuildsRelatedCompoundHeadersAndAcceptsRelatedResponses",
                        displayName: "Client builds related compounded request headers and accepts related response headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient();
                            GrantCredits(session, 3);

                            Smb2Header createHeader = session.CreateRequestHeader(Smb2Command.Create, treeId: 42, sessionId: session.SessionId!.Value);
                            Smb2Header closeHeader = session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: session.SessionId.Value);
                            TestAssertions.Equal(Smb2HeaderFlags.RelatedOperations | Smb2HeaderFlags.Signed, closeHeader.Flags, "Expected authenticated related compounded requests to preserve SMB2 signing while marking the request as related.");

                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(createHeader, flags: Smb2HeaderFlags.ServerToRedir), Array.Empty<byte>()),
                                    new Smb2CompoundPacketEntry(CreateResponseHeader(closeHeader, flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations), Array.Empty<byte>())
                                });

                            session.ApplyCompoundResponsePacket(responsePacket);
                            TestAssertions.Equal(3, session.AvailableCredits, "Expected related compounded response headers to restore the client credit window.");
                            TestAssertions.Equal(0, session.PendingRequestCount, "Expected related compounded response headers to complete every pending request.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client file-I/O suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientFileIoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.FileIo",
                displayName: "Client file-I/O handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientBuildsFileIoRequestsAndTracksOpenLifecycle",
                        displayName: "Client builds create/read/write/flush/close requests and tracks open lifecycle state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            Smb2CreateRequest createRequest = session.CreateCreateRequest(42, "folder/notes.txt");
                            TestAssertions.Equal("folder\\notes.txt", createRequest.Name, "Expected the client to normalize relative create paths.");

                            Smb2CreateRequest deleteOnCloseRequest = session.CreateCreateRequest(
                                42,
                                "folder/temp.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose);
                            TestAssertions.Equal(0xC0010000U, deleteOnCloseRequest.DesiredAccess, "Unexpected delete-on-close desired-access mask.");
                            TestAssertions.Equal(
                                Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                deleteOnCloseRequest.CreateOptions,
                                "Unexpected delete-on-close create options.");

                            Smb2CreateRequest directoryCreateRequest = session.CreateCreateRequest(
                                42,
                                "folder/new-directory",
                                desiredAccess: 0x80000000U,
                                fileAttributes: FileAttributes.Directory,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Create,
                                createOptions: Smb2CreateOptions.DirectoryFile);
                            TestAssertions.Equal("folder\\new-directory", directoryCreateRequest.Name, "Expected the client to normalize relative directory-create paths.");
                            TestAssertions.Equal(FileAttributes.Directory, directoryCreateRequest.FileAttributes, "Unexpected directory-create file attributes.");
                            TestAssertions.Equal(Smb2CreateDisposition.Create, directoryCreateRequest.CreateDisposition, "Unexpected directory-create disposition.");
                            TestAssertions.Equal(Smb2CreateOptions.DirectoryFile, directoryCreateRequest.CreateOptions, "Unexpected directory-create options.");

                            Smb2CreateRequest directoryDeleteOnCloseRequest = session.CreateCreateRequest(
                                42,
                                "folder/transient-directory",
                                desiredAccess: 0x80010000U,
                                fileAttributes: FileAttributes.Directory,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.OpenIf,
                                createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose);
                            TestAssertions.Equal(0x80010000U, directoryDeleteOnCloseRequest.DesiredAccess, "Unexpected directory delete-on-close desired-access mask.");
                            TestAssertions.Equal(
                                Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                directoryDeleteOnCloseRequest.CreateOptions,
                                "Unexpected directory delete-on-close create options.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "folder/notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Created,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 100,
                                    VolatileFileId = 101,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            TestAssertions.Equal(1, session.OpenCount, "Expected the client to track the newly created open.");
                            TestAssertions.Equal("folder\\notes.txt", openState.Path, "Unexpected tracked client open path.");

                            Smb2WriteRequest writeRequest = session.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, new byte[] { 0x01, 0x02, 0x03 }, 0);
                            TestAssertions.SequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, writeRequest.DataBuffer, "Unexpected client write payload.");
                            uint writeCount = session.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2WriteResponse
                            {
                                Count = 3
                            });
                            TestAssertions.Equal(3U, writeCount, "Unexpected client-observed write count.");

                            Smb2FlushRequest flushRequest = session.CreateFlushRequest(openState.PersistentFileId, openState.VolatileFileId);
                            TestAssertions.Equal(101UL, flushRequest.VolatileFileId, "Unexpected client flush-request volatile file identifier.");
                            session.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2FlushResponse());

                            Smb2ReadRequest readRequest = session.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 3, 0, minimumCount: 1);
                            TestAssertions.Equal(1U, readRequest.MinimumCount, "Unexpected client read-request minimum count.");
                            byte[] readBytes = session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2ReadResponse
                            {
                                DataBuffer = new byte[] { 0x01, 0x02, 0x03 },
                                DataRemaining = 0,
                                Flags = 0
                            });
                            TestAssertions.SequenceEqual(new byte[] { 0x01, 0x02, 0x03 }, readBytes, "Unexpected client-observed read payload.");

                            Smb2CloseRequest closeRequest = session.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId, postQueryAttributes: true);
                            TestAssertions.Equal(Smb2CloseFlags.PostQueryAttributes, closeRequest.Flags, "Unexpected client close-request flags.");
                            session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2CloseResponse
                            {
                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                EndOfFile = 3,
                                FileAttributes = FileAttributes.Normal
                            });
                            TestAssertions.Equal(0, session.OpenCount, "Expected the client to drop the tracked open after close.");

                            session.ApplyCreateResult(
                                42,
                                "folder\\transient.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Created,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 200,
                                    VolatileFileId = 201,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            TestAssertions.Equal(1, session.OpenCount, "Expected the client to track a second open before tree disconnect.");

                            session.ApplyTreeDisconnectResult(42, NtStatus.Success, new Smb2TreeDisconnectResponse());
                            TestAssertions.Equal(0, session.OpenCount, "Expected tree disconnect to drop all opens on the disconnected tree.");
                            TestAssertions.Equal(0, session.ConnectedTreeIds.Length, "Expected tree disconnect to remove the connected tree.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientRejectsInvalidFileIoStateAndHandlesEof",
                        displayName: "Client rejects invalid file-I/O state transitions and reports EOF cleanly",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateCreateRequest(99, "notes.txt"),
                                "Creating a file request on an unknown tree should fail.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateReadRequest(1, 2, 4, 0),
                                "Reading from an unknown open should fail.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 300,
                                    VolatileFileId = 301,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            byte[] eofBytes = session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.EndOfFile, new Smb2ReadResponse());
                            TestAssertions.Equal(0, eofBytes.Length, "Expected EOF reads to return an empty payload.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2ReadResponse
                                {
                                    DataBuffer = Array.Empty<byte>(),
                                    DataRemaining = 0,
                                    Flags = 0
                                }),
                                "Successful read results with an empty payload should fail validation.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientBuildsSmb302DurableHandleV2RequestsAndTracksReconnectState",
                        displayName: "Client builds SMB 3.0.2 durable-handle v2 requests and tracks reconnect state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient(SmbDialect.Smb302);
                            session.ApplyTreeConnectResult("public", 42, NtStatus.Success, CreateTreeConnectSuccessResponse());

                            Smb2CreateRequest createRequest = session.CreateCreateRequest(
                                42,
                                "shared.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Open,
                                requestedOplockLevel: Smb2OplockLevel.Batch,
                                requestDurableHandle: true);
                            Smb2CreateContext[] initialCreateContexts = Smb2CreateContextCodec.Decode(createRequest.CreateContexts);
                            TestAssertions.Equal(1, initialCreateContexts.Length, "Expected the bounded SMB 3.0.2 durable open to carry a single durable-handle v2 request context.");
                            TestAssertions.True(Smb2DurableHandleRequestV2Context.IsMatch(initialCreateContexts[0]), "Expected the bounded SMB 3.0.2 durable open to use the durable-handle v2 request context.");
                            Smb2DurableHandleRequestV2Context durableHandleRequestV2 = Smb2DurableHandleRequestV2Context.ReadFrom(initialCreateContexts[0]);
                            TestAssertions.False(durableHandleRequestV2.CreateGuid == Guid.Empty, "Expected the bounded SMB 3.0.2 durable-handle v2 request to generate a non-empty create GUID.");
                            TestAssertions.Equal(0U, durableHandleRequestV2.Timeout, "Expected the bounded SMB 3.0.2 durable-handle v2 request to use the managed default timeout request.");
                            TestAssertions.Equal(Smb2DurableHandleFlags.None, durableHandleRequestV2.Flags, "Expected the bounded SMB 3.0.2 durable-handle v2 request to stay non-persistent.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Batch,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 900,
                                    VolatileFileId = 901,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2DurableHandleResponseV2Context
                                        {
                                            Timeout = 300000,
                                            Flags = Smb2DurableHandleFlags.None
                                        }.ToCreateContext()
                                    })
                                },
                                createRequest);
                            TestAssertions.True(openState.IsDurable, "Expected the bounded SMB 3.0.2 durable create result to be tracked as durable.");
                            TestAssertions.True(openState.UsesDurableHandleV2, "Expected the bounded SMB 3.0.2 durable create result to be tracked as durable-handle v2.");
                            TestAssertions.False(openState.DurableCreateGuid == Guid.Empty, "Expected the bounded SMB 3.0.2 durable create result to preserve the request create GUID.");
                            TestAssertions.Equal(300000U, openState.DurableTimeoutMs, "Expected the bounded SMB 3.0.2 durable create result to preserve the granted durable timeout.");
                            TestAssertions.False(openState.IsPersistent, "Expected the bounded SMB 3.0.2 durable create result to remain non-persistent.");

                            Smb2CreateRequest reconnectRequest = session.CreateDurableReconnectCreateRequest(
                                42,
                                "shared.txt",
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                requestedOplockLevel: Smb2OplockLevel.Batch,
                                durableCreateGuid: openState.DurableCreateGuid,
                                useDurableHandleV2: openState.UsesDurableHandleV2);
                            Smb2CreateContext[] reconnectCreateContexts = Smb2CreateContextCodec.Decode(reconnectRequest.CreateContexts);
                            TestAssertions.Equal(1, reconnectCreateContexts.Length, "Expected the bounded SMB 3.0.2 durable reconnect to carry a single durable-handle v2 reconnect context.");
                            TestAssertions.True(Smb2DurableHandleReconnectV2Context.IsMatch(reconnectCreateContexts[0]), "Expected the bounded SMB 3.0.2 durable reconnect to use the durable-handle v2 reconnect context.");
                            Smb2DurableHandleReconnectV2Context durableHandleReconnectV2 = Smb2DurableHandleReconnectV2Context.ReadFrom(reconnectCreateContexts[0]);
                            TestAssertions.Equal(openState.PersistentFileId, durableHandleReconnectV2.PersistentFileId, "Expected the bounded SMB 3.0.2 durable reconnect to preserve the persistent file identifier.");
                            TestAssertions.Equal(openState.VolatileFileId, durableHandleReconnectV2.VolatileFileId, "Expected the bounded SMB 3.0.2 durable reconnect to preserve the original volatile file identifier.");
                            TestAssertions.Equal(openState.DurableCreateGuid, durableHandleReconnectV2.CreateGuid, "Expected the bounded SMB 3.0.2 durable reconnect to preserve the create GUID.");
                            TestAssertions.Equal(Smb2DurableHandleFlags.None, durableHandleReconnectV2.Flags, "Expected the bounded SMB 3.0.2 durable reconnect to stay non-persistent.");

                            OpenState reconnectedOpenState = session.ApplyCreateResult(
                                42,
                                "shared.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.Batch,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 900,
                                    VolatileFileId = 902,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2DurableHandleResponseV2Context
                                        {
                                            Timeout = 300000,
                                            Flags = Smb2DurableHandleFlags.None
                                        }.ToCreateContext()
                                    })
                                },
                                reconnectRequest);
                            TestAssertions.True(reconnectedOpenState.UsesDurableHandleV2, "Expected the bounded SMB 3.0.2 durable reconnect result to remain durable-handle v2.");
                            TestAssertions.Equal(openState.DurableCreateGuid, reconnectedOpenState.DurableCreateGuid, "Expected the bounded SMB 3.0.2 durable reconnect result to preserve the original create GUID.");
                            TestAssertions.Equal(300000U, reconnectedOpenState.DurableTimeoutMs, "Expected the bounded SMB 3.0.2 durable reconnect result to preserve the granted durable timeout.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.FileIo",
                        caseId: "ClientBuildsSupersedeAndOverwriteCreateRequests",
                        displayName: "Client builds bounded overwrite, supersede, and create-attribute requests and rejects supersede without delete access",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            Smb2CreateRequest overwriteIfRequest = session.CreateCreateRequest(
                                42,
                                "folder/replace.txt",
                                desiredAccess: 0xC0000000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.OverwriteIf,
                                fileAttributes: FileAttributes.Hidden);
                            TestAssertions.Equal("folder\\replace.txt", overwriteIfRequest.Name, "Expected overwrite-if requests to preserve the normalized path.");
                            TestAssertions.Equal(Smb2CreateDisposition.OverwriteIf, overwriteIfRequest.CreateDisposition, "Unexpected overwrite-if create disposition.");
                            TestAssertions.Equal(FileAttributes.Hidden, overwriteIfRequest.FileAttributes, "Expected overwrite-if requests to preserve create-time file attributes.");

                            Smb2CreateRequest supersedeRequest = session.CreateCreateRequest(
                                42,
                                "folder/supersede.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Supersede);
                            TestAssertions.Equal(Smb2CreateDisposition.Supersede, supersedeRequest.CreateDisposition, "Unexpected supersede create disposition.");
                            TestAssertions.Equal(0xC0010000U, supersedeRequest.DesiredAccess, "Expected FILE_SUPERSEDE requests to preserve DELETE access.");

                            Smb2CreateRequest deleteOnCloseReadOnlyRequest = session.CreateCreateRequest(
                                42,
                                "folder/transient-readonly.txt",
                                desiredAccess: 0xC0010000U,
                                shareAccess: 0x00000007U,
                                createDisposition: Smb2CreateDisposition.Create,
                                createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                fileAttributes: FileAttributes.ReadOnly);
                            TestAssertions.Equal(FileAttributes.ReadOnly, deleteOnCloseReadOnlyRequest.FileAttributes, "Expected delete-on-close create requests to preserve read-only file attributes.");
                            TestAssertions.Equal(
                                Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                deleteOnCloseReadOnlyRequest.CreateOptions,
                                "Expected delete-on-close create requests to preserve the requested create options.");

                            OpenState overwrittenOpen = session.ApplyCreateResult(
                                42,
                                "folder/replace.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Overwritten,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 320,
                                    VolatileFileId = 321,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            session.ApplyCloseResult(overwrittenOpen.PersistentFileId, overwrittenOpen.VolatileFileId, NtStatus.Success, new Smb2CloseResponse());

                            OpenState supersededOpen = session.ApplyCreateResult(
                                42,
                                "folder/supersede.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Superseded,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 322,
                                    VolatileFileId = 323,
                                    CreateContexts = Array.Empty<byte>()
                                });
                            session.ApplyCloseResult(supersededOpen.PersistentFileId, supersededOpen.VolatileFileId, NtStatus.Success, new Smb2CloseResponse());
                            TestAssertions.Equal(0, session.OpenCount, "Expected superseded and overwritten opens to close cleanly.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => session.CreateCreateRequest(
                                    42,
                                    "folder/invalid-supersede.txt",
                                    desiredAccess: 0xC0000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Supersede),
                                "FILE_SUPERSEDE should require DELETE access.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client metadata suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientMetadataSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Metadata",
                displayName: "Client metadata request and state handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Metadata",
                        caseId: "ClientBuildsMetadataRequestsAndTracksRenameDeleteState",
                        displayName: "Client builds metadata and directory-enumeration requests and tracks rename and delete-pending state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "folder\\notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Created,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 400,
                                    VolatileFileId = 401,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2QueryInfoRequest queryInfoRequest = session.CreateQueryInfoRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                FileInformationClass.NetworkOpenInformation,
                                outputBufferLength: 512);
                            TestAssertions.Equal(Smb2InfoType.File, queryInfoRequest.InfoType, "Expected query-info requests to target file information.");
                            TestAssertions.Equal(512U, queryInfoRequest.OutputBufferLength, "Unexpected query-info output-buffer length.");

                            Smb2SetInfoRequest basicInfoRequest = session.CreateSetBasicInfoRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new FileBasicInformation
                                {
                                    CreationTime = 0x0102030405060708UL,
                                    LastAccessTime = 0x1112131415161718UL,
                                    LastWriteTime = 0x1122334455667788UL,
                                    ChangeTime = 0x2122232425262728UL,
                                    FileAttributes = FileAttributes.Hidden
                                });
                            FileBasicInformation basicInfoPayload = FileBasicInformation.ReadFrom(basicInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.BasicInformation, basicInfoRequest.FileInfoClass, "Unexpected set-info basic information class.");
                            TestAssertions.Equal(0x0102030405060708UL, basicInfoPayload.CreationTime, "Unexpected FILE_BASIC_INFORMATION creation time.");
                            TestAssertions.Equal(0x1112131415161718UL, basicInfoPayload.LastAccessTime, "Unexpected FILE_BASIC_INFORMATION last-access time.");
                            TestAssertions.Equal(0x1122334455667788UL, basicInfoPayload.LastWriteTime, "Unexpected FILE_BASIC_INFORMATION last-write time.");
                            TestAssertions.Equal(0x2122232425262728UL, basicInfoPayload.ChangeTime, "Unexpected FILE_BASIC_INFORMATION change time.");
                            TestAssertions.Equal(FileAttributes.Hidden, basicInfoPayload.FileAttributes, "Unexpected FILE_BASIC_INFORMATION attributes.");

                            Smb2SetInfoRequest stickyBasicInfoRequest = session.CreateSetBasicInfoRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new FileBasicInformation
                                {
                                    CreationTime = UInt64.MaxValue,
                                    LastAccessTime = UInt64.MaxValue,
                                    LastWriteTime = UInt64.MaxValue - 1,
                                    ChangeTime = UInt64.MaxValue,
                                    FileAttributes = FileAttributes.Hidden
                                });
                            FileBasicInformation stickyBasicInfoPayload = FileBasicInformation.ReadFrom(stickyBasicInfoRequest.Buffer);
                            TestAssertions.Equal(UInt64.MaxValue, stickyBasicInfoPayload.CreationTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky creation-time directives.");
                            TestAssertions.Equal(UInt64.MaxValue, stickyBasicInfoPayload.LastAccessTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky last-access directives.");
                            TestAssertions.Equal(UInt64.MaxValue - 1, stickyBasicInfoPayload.LastWriteTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky last-write directives.");
                            TestAssertions.Equal(UInt64.MaxValue, stickyBasicInfoPayload.ChangeTime, "Expected FILE_BASIC_INFORMATION requests to preserve sticky change-time directives.");

                            Smb2SetInfoRequest allocationInfoRequest = session.CreateSetAllocationInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 32768);
                            FileAllocationInformation allocationInfoPayload = FileAllocationInformation.ReadFrom(allocationInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.AllocationInformation, allocationInfoRequest.FileInfoClass, "Unexpected set-info allocation information class.");
                            TestAssertions.Equal(32768UL, allocationInfoPayload.AllocationSize, "Unexpected FILE_ALLOCATION_INFORMATION allocation size.");

                            Smb2SetInfoRequest endOfFileInfoRequest = session.CreateSetEndOfFileInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 2048);
                            FileEndOfFileInformation endOfFileInfoPayload = FileEndOfFileInformation.ReadFrom(endOfFileInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.EndOfFileInformation, endOfFileInfoRequest.FileInfoClass, "Unexpected set-info EOF information class.");
                            TestAssertions.Equal(2048UL, endOfFileInfoPayload.EndOfFile, "Unexpected FILE_END_OF_FILE_INFORMATION EOF size.");

                            Smb2SetInfoRequest renameInfoRequest = session.CreateSetRenameInfoRequest(openState.PersistentFileId, openState.VolatileFileId, "archive/notes-renamed.txt", replaceIfExists: true);
                            FileRenameInformationType2 renameInfoPayload = FileRenameInformationType2.ReadFrom(renameInfoRequest.Buffer);
                            TestAssertions.Equal(FileInformationClass.RenameInformation, renameInfoRequest.FileInfoClass, "Unexpected set-info rename information class.");
                            TestAssertions.True(renameInfoPayload.ReplaceIfExists, "Expected FILE_RENAME_INFORMATION_TYPE_2 to preserve ReplaceIfExists.");
                            TestAssertions.Equal("archive\\notes-renamed.txt", renameInfoPayload.FileName, "Expected rename paths to be normalized.");

                            Smb2CreateRequest directoryCreateRequest = session.CreateCreateRequest(
                                42,
                                "folder",
                                desiredAccess: 0x80000000U,
                                createDisposition: Smb2CreateDisposition.Open,
                                createOptions: Smb2CreateOptions.DirectoryFile);
                            TestAssertions.Equal(Smb2CreateOptions.DirectoryFile, directoryCreateRequest.CreateOptions, "Expected directory create requests to preserve the directory create option.");
                            TestAssertions.Equal("folder", directoryCreateRequest.Name, "Expected directory create requests to preserve the normalized path.");

                            OpenState directoryOpenState = session.ApplyCreateResult(
                                42,
                                "folder",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Directory,
                                    PersistentFileId = 410,
                                    VolatileFileId = 411,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2QueryDirectoryRequest queryDirectoryRequest = session.CreateQueryDirectoryRequest(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                FileInformationClass.DirectoryInformation,
                                outputBufferLength: 256,
                                fileNamePattern: "*.txt",
                                flags: Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry);
                            TestAssertions.Equal(FileInformationClass.DirectoryInformation, queryDirectoryRequest.FileInfoClass, "Unexpected query-directory information class.");
                            TestAssertions.Equal("*.txt", queryDirectoryRequest.FileNamePattern, "Unexpected query-directory search pattern.");
                            TestAssertions.Equal(
                                Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                queryDirectoryRequest.Flags,
                                "Unexpected query-directory flags.");

                            byte[] queryDirectoryBytes = session.ApplyQueryDirectoryResult(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2QueryDirectoryResponse
                                {
                                    OutputBuffer = FileDirectoryInformationEntry.EncodeEntries(new FileDirectoryInformationEntry[]
                                    {
                                        new FileDirectoryInformationEntry
                                        {
                                            FileName = "notes.txt",
                                            EndOfFile = 17,
                                            AllocationSize = 32,
                                            FileAttributes = FileAttributes.Archive
                                        }
                                    })
                                });
                            FileDirectoryInformationEntry[] queryDirectoryEntries = FileDirectoryInformationEntry.DecodeEntries(queryDirectoryBytes);
                            TestAssertions.Equal(1, queryDirectoryEntries.Length, "Expected a single client-observed directory entry.");
                            TestAssertions.Equal("notes.txt", queryDirectoryEntries[0].FileName, "Unexpected client-observed directory entry name.");

                            byte[] exhaustedDirectoryBytes = session.ApplyQueryDirectoryResult(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                NtStatus.NoMoreFiles,
                                new Smb2QueryDirectoryResponse());
                            TestAssertions.Equal(0, exhaustedDirectoryBytes.Length, "Expected exhausted query-directory results to return an empty payload.");

                            Smb2SetInfoRequest directoryRenameInfoRequest = session.CreateSetRenameInfoRequest(
                                directoryOpenState.PersistentFileId,
                                directoryOpenState.VolatileFileId,
                                "archive/folder-renamed");
                            FileRenameInformationType2 directoryRenameInfoPayload = FileRenameInformationType2.ReadFrom(directoryRenameInfoRequest.Buffer);
                            TestAssertions.Equal("archive\\folder-renamed", directoryRenameInfoPayload.FileName, "Expected directory rename paths to be normalized.");

                            byte[] queryResultBytes = session.ApplyQueryInfoResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2QueryInfoResponse
                                {
                                    OutputBuffer = new FileNetworkOpenInformation
                                    {
                                        AllocationSize = 2048,
                                        EndOfFile = 17,
                                        FileAttributes = FileAttributes.Archive
                                    }.ToByteArray()
                                });
                            FileNetworkOpenInformation queryResult = FileNetworkOpenInformation.ReadFrom(queryResultBytes);
                            TestAssertions.Equal(2048UL, queryResult.AllocationSize, "Unexpected client-observed FILE_NETWORK_OPEN_INFORMATION allocation size.");
                            TestAssertions.Equal(17UL, queryResult.EndOfFile, "Unexpected client-observed FILE_NETWORK_OPEN_INFORMATION EOF size.");

                            session.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2SetInfoResponse(), deletePending: true);
                            TestAssertions.True(openState.IsDeletePending, "Expected successful disposition updates to mark the tracked open as delete-pending.");

                            session.ApplySetRenameInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2SetInfoResponse(), "archive/notes-renamed.txt");
                            TestAssertions.Equal("archive\\notes-renamed.txt", openState.Path, "Expected successful rename updates to normalize the tracked open path.");

                            session.ApplySetRenameInfoResult(directoryOpenState.PersistentFileId, directoryOpenState.VolatileFileId, NtStatus.Success, new Smb2SetInfoResponse(), "archive/folder-renamed");
                            TestAssertions.Equal("archive\\folder-renamed", directoryOpenState.Path, "Expected successful directory rename updates to normalize the tracked directory-open path.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Metadata",
                        caseId: "ClientRejectsMetadataRequestsForUnknownOpenOrFailedStatus",
                        displayName: "Client rejects metadata requests for unknown opens and preserves state on failed responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateQueryInfoRequest(1, 2, FileInformationClass.BasicInformation),
                                "Query-info requests should fail for an unknown open.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateSetAllocationInfoRequest(1, 2, 128),
                                "Set-info requests should fail for an unknown open.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateQueryDirectoryRequest(1, 2, FileInformationClass.DirectoryInformation),
                                "Query-directory requests should fail for an unknown open.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 500,
                                    VolatileFileId = 501,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.BufferTooSmall, new Smb2QueryInfoResponse()),
                                "Failed query-info results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.AccessDenied, new Smb2SetInfoResponse(), deletePending: true),
                                "Failed set-info disposition results should throw.");
                            TestAssertions.False(openState.IsDeletePending, "Failed set-info disposition results should not mutate tracked delete-pending state.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyQueryDirectoryResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.BufferTooSmall, new Smb2QueryDirectoryResponse()),
                                "Failed query-directory results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplySetRenameInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.AccessDenied, new Smb2SetInfoResponse(), "archive\\blocked.txt"),
                                "Failed set-info rename results should throw.");
                            TestAssertions.Equal("notes.txt", openState.Path, "Failed set-info rename results should not mutate the tracked path.");

                            OpenCifsStatusException queryInfoException;

                            try
                            {
                                session.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.BufferTooSmall, new Smb2QueryInfoResponse());
                                throw new InvalidOperationException("Expected query-info failure to raise an SMB status exception.");
                            }
                            catch (OpenCifsStatusException exception)
                            {
                                queryInfoException = exception;
                            }

                            TestAssertions.Equal(Smb2Command.QueryInfo, queryInfoException.Command, "Expected query-info failure to report the QueryInfo command.");
                            TestAssertions.Equal(NtStatus.BufferTooSmall, queryInfoException.Status, "Expected query-info failure to report STATUS_BUFFER_TOO_SMALL.");
                            TestAssertions.Equal(OpenCifsErrorCategory.ProtocolError, queryInfoException.Category, "Expected query-info failure to normalize to ProtocolError.");

                            OpenCifsStatusException setInfoException;

                            try
                            {
                                session.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.AccessDenied, new Smb2SetInfoResponse(), deletePending: true);
                                throw new InvalidOperationException("Expected set-info failure to raise an SMB status exception.");
                            }
                            catch (OpenCifsStatusException exception)
                            {
                                setInfoException = exception;
                            }

                            TestAssertions.Equal(Smb2Command.SetInfo, setInfoException.Command, "Expected set-info failure to report the SetInfo command.");
                            TestAssertions.Equal(NtStatus.AccessDenied, setInfoException.Status, "Expected set-info failure to report STATUS_ACCESS_DENIED.");
                            TestAssertions.Equal(OpenCifsErrorCategory.AccessDenied, setInfoException.Category, "Expected set-info failure to normalize to AccessDenied.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the client locking suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientLockingSuite()
        {
            return ClientLockingSuiteBuilder.Build();
        }

        /// <summary>
        /// Build the client IOCTL suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ClientIoctlSuite()
        {
            return ClientIoctlSuiteBuilder.Build();
        }

    }
}
