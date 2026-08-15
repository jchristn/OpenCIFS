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
    internal static class LoopbackDurableHandleSuiteBuilder
    {
        internal static TestSuiteDescriptor LoopbackDurableHandleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackDurable",
                displayName: "Loopback durable-handle reconnect coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerReconnectDurableBatchOpenAcrossHosts",
                        displayName: "Client and server loopback reconnect a durable batch open across hosts that share server state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial loopback open to be granted durable reconnect state.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, durableOpen.OplockLevel, "Expected the initial loopback durable open to receive a batch oplock.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2CreateRequest reconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, reconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", reconnectResult.Status, reconnectResult.Response);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected loopback open to stay durable.");
                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(reconnectedOpen.VolatileFileId == durableOpen.VolatileFileId, "Expected durable reconnect to allocate a fresh volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, reconnectedOpen.OplockLevel, "Expected durable reconnect to preserve the granted batch oplock.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateReadRequest(
                                        reconnectedOpen.PersistentFileId,
                                        reconnectedOpen.VolatileFileId,
                                        length: 32,
                                        offset: 0,
                                        minimumCount: 1));
                                byte[] buffer = secondClient.ApplyReadResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    readResult.Status,
                                    readResult.Response);
                                TestAssertions.Equal("durable-data", Encoding.UTF8.GetString(buffer), "Expected the reconnected durable open to preserve file access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResult.Status,
                                    closeResult.Response);
                                TestAssertions.Equal(0, secondClient.OpenCount, "Expected the loopback durable reconnect flow to leave no tracked opens after close.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerReconnectEncryptedDurableBatchOpenAcrossHostsUnderSmb302",
                        displayName: "Client and server loopback reconnect an encrypted durable batch open across hosts under SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropEncryptedDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState, maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: true);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState, maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: true);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost, maximumDialect: SmbDialect.Smb302, preferEncryption: true);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateEncryptedLoopbackSessionAndTree(firstHost, firstClient, credential);

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                Smb2CompoundPacket initialOpenResponsePacket = RoundTripEncryptedPacket(
                                    firstHost,
                                    firstClient,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            firstClient.CreateRequestHeader(Smb2Command.Create, firstTreeId, sessionId: firstClient.SessionId!.Value),
                                            initialOpenRequest.ToByteArray())
                                    }),
                                    "encrypted durable create");
                                OpenState durableOpen = firstClient.ApplyCreateResult(
                                    firstTreeId,
                                    "shared.txt",
                                    initialOpenResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(initialOpenResponsePacket.Entries[0].Header.Command, initialOpenResponsePacket.Entries[0].Payload)),
                                    initialOpenRequest);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial encrypted durable open to be granted durable reconnect state.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, durableOpen.OplockLevel, "Expected the initial encrypted durable open to receive a batch oplock.");
                                TestAssertions.True(durableOpen.UsesDurableHandleV2, "Expected the initial encrypted SMB 3.0.2 durable open to use durable-handle v2.");
                                TestAssertions.False(durableOpen.DurableCreateGuid == Guid.Empty, "Expected the initial encrypted SMB 3.0.2 durable open to preserve a non-empty durable create GUID.");
                                TestAssertions.Equal(300000U, durableOpen.DurableTimeoutMs, "Expected the initial encrypted SMB 3.0.2 durable open to preserve the bounded durable timeout.");
                                TestAssertions.False(durableOpen.IsPersistent, "Expected the initial encrypted SMB 3.0.2 durable open to remain non-persistent.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost, maximumDialect: SmbDialect.Smb302, preferEncryption: true);
                                uint secondTreeId = AuthenticateEncryptedLoopbackSessionAndTree(secondHost, secondClient, credential);

                                Smb2CreateRequest reconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    durableCreateGuid: durableOpen.DurableCreateGuid,
                                    useDurableHandleV2: durableOpen.UsesDurableHandleV2);
                                Smb2CompoundPacket reconnectResponsePacket = RoundTripEncryptedPacket(
                                    secondHost,
                                    secondClient,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            secondClient.CreateRequestHeader(Smb2Command.Create, secondTreeId, sessionId: secondClient.SessionId!.Value),
                                            reconnectRequest.ToByteArray())
                                    }),
                                    "encrypted durable reconnect");
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(
                                    secondTreeId,
                                    "shared.txt",
                                    reconnectResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(reconnectResponsePacket.Entries[0].Header.Command, reconnectResponsePacket.Entries[0].Payload)),
                                    reconnectRequest);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the encrypted reconnected open to remain durable.");
                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected encrypted durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(reconnectedOpen.VolatileFileId == durableOpen.VolatileFileId, "Expected encrypted durable reconnect to allocate a fresh volatile file identifier.");
                                TestAssertions.True(reconnectedOpen.UsesDurableHandleV2, "Expected the encrypted SMB 3.0.2 durable reconnect to remain on durable-handle v2.");
                                TestAssertions.Equal(durableOpen.DurableCreateGuid, reconnectedOpen.DurableCreateGuid, "Expected the encrypted SMB 3.0.2 durable reconnect to preserve the durable create GUID.");
                                TestAssertions.Equal(300000U, reconnectedOpen.DurableTimeoutMs, "Expected the encrypted SMB 3.0.2 durable reconnect to preserve the bounded durable timeout.");

                                Smb2CompoundPacket readResponsePacket = RoundTripEncryptedPacket(
                                    secondHost,
                                    secondClient,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            secondClient.CreateRequestHeader(Smb2Command.Read, secondTreeId, sessionId: secondClient.SessionId.Value),
                                            secondClient.CreateReadRequest(
                                                reconnectedOpen.PersistentFileId,
                                                reconnectedOpen.VolatileFileId,
                                                length: 32,
                                                offset: 0,
                                                minimumCount: 1).ToByteArray())
                                    }),
                                    "encrypted durable read");
                                byte[] buffer = secondClient.ApplyReadResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    readResponsePacket.Entries[0].Header.Status,
                                    Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(readResponsePacket.Entries[0].Header.Command, readResponsePacket.Entries[0].Payload)));
                                TestAssertions.Equal("durable-data", Encoding.UTF8.GetString(buffer), "Expected the encrypted durable reconnect path to preserve file access.");

                                Smb2CompoundPacket closeResponsePacket = RoundTripEncryptedPacket(
                                    secondHost,
                                    secondClient,
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            secondClient.CreateRequestHeader(Smb2Command.Close, secondTreeId, sessionId: secondClient.SessionId.Value),
                                            secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId).ToByteArray())
                                    }),
                                    "encrypted durable close");
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResponsePacket.Entries[0].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(closeResponsePacket.Entries[0].Header.Command, closeResponsePacket.Entries[0].Payload)));
                                TestAssertions.Equal(0, secondClient.OpenCount, "Expected the encrypted durable reconnect flow to leave no tracked opens after close.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerReconnectDurableLeaseOpenAcrossHosts",
                        displayName: "Client and server loopback reconnect a durable lease-backed open across hosts that share server state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurableLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                Guid durableClientGuid = Guid.NewGuid();
                                byte[] leaseKey = new byte[16];
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 33);
                                }

                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost, durableClientGuid);
                                TestAssertions.Equal(SmbDialect.Smb21, firstClient.NegotiatedDialect, "Expected the initial durable lease loopback session to negotiate SMB 2.1.");
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestDurableHandle: true,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial loopback lease-backed open to be granted durable reconnect state.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, durableOpen.OplockLevel, "Expected the initial loopback durable lease open to receive an SMB 2.1 lease.");
                                TestAssertions.SequenceEqual(leaseKey, durableOpen.LeaseKey, "Expected the initial loopback durable lease open to preserve the requested lease key.");
                                TestAssertions.Equal(leaseState, durableOpen.LeaseState, "Expected the initial loopback durable lease open to preserve the granted lease state.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost, durableClientGuid);
                                TestAssertions.Equal(SmbDialect.Smb21, secondClient.NegotiatedDialect, "Expected the reconnect loopback session to negotiate SMB 2.1.");
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2CreateRequest reconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, reconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", reconnectResult.Status, reconnectResult.Response);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected loopback durable lease open to stay durable.");
                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable lease reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(reconnectedOpen.VolatileFileId == durableOpen.VolatileFileId, "Expected durable lease reconnect to allocate a fresh volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, reconnectedOpen.OplockLevel, "Expected durable lease reconnect to preserve the granted lease-backed oplock level.");
                                TestAssertions.SequenceEqual(leaseKey, reconnectedOpen.LeaseKey, "Expected durable lease reconnect to preserve the lease key.");
                                TestAssertions.Equal(leaseState, reconnectedOpen.LeaseState, "Expected durable lease reconnect to preserve the lease state.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateReadRequest(
                                        reconnectedOpen.PersistentFileId,
                                        reconnectedOpen.VolatileFileId,
                                        length: 32,
                                        offset: 0,
                                        minimumCount: 1));
                                byte[] buffer = secondClient.ApplyReadResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    readResult.Status,
                                    readResult.Response);
                                TestAssertions.Equal("durable-lease-data", Encoding.UTF8.GetString(buffer), "Expected the reconnected durable lease open to preserve file access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResult.Status,
                                    closeResult.Response);
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerRejectMismatchedDurableReconnectAndPreserveDetachedOpen",
                        displayName: "Client and server loopback reject mismatched durable reconnect requests and preserve the detached open for the correct retry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2CreateRequest invalidReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "wrong.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, invalidReconnectRequest);
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidReconnectResult.Status, "Expected the loopback durable reconnect flow to reject the wrong path.");

                                Smb2CreateRequest validReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, validReconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", validReconnectResult.Status, validReconnectResult.Response);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the detached durable open to remain reconnectable after a mismatched retry.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResult.Status,
                                    closeResult.Response);
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerRejectMissingOrMismatchedLeaseReconnectAndPreserveDetachedOpen",
                        displayName: "Client and server loopback reject missing or mismatched lease reconnect requests and preserve the detached durable open for the correct retry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurableLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                Guid durableClientGuid = Guid.NewGuid();
                                byte[] leaseKey = new byte[16];
                                byte[] wrongLeaseKey = new byte[16];
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 49);
                                    wrongLeaseKey[index] = (byte)(index + 81);
                                }

                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost, durableClientGuid);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestDurableHandle: true,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost, durableClientGuid);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                Smb2CreateRequest missingLeaseReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> missingLeaseReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, missingLeaseReconnectRequest);
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingLeaseReconnectResult.Status, "Expected the loopback durable lease reconnect flow to reject a missing lease create context.");

                                Smb2CreateRequest wrongLeaseReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: leaseState,
                                    leaseKey: wrongLeaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> wrongLeaseReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, wrongLeaseReconnectRequest);
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, wrongLeaseReconnectResult.Status, "Expected the loopback durable lease reconnect flow to reject the wrong lease key.");

                                Smb2CreateRequest validReconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey);
                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, validReconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", validReconnectResult.Status, validReconnectResult.Response);
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the detached durable lease open to remain reconnectable after rejected retries.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(
                                    reconnectedOpen.PersistentFileId,
                                    reconnectedOpen.VolatileFileId,
                                    closeResult.Status,
                                    closeResult.Response);
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackDurable",
                        caseId: "ClientAndServerPreserveDurableByteRangeLocksAcrossReconnect",
                        displayName: "Client and server loopback preserve durable byte-range locks across reconnect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState);

                            try
                            {
                                OpenCifsClientSession firstClient = CreateNegotiatedClient(firstHost);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint firstTreeId = AuthenticateLoopbackSessionAndTree(firstHost, firstClient, credential);
                                ulong firstSessionId = firstClient.SessionId!.Value;

                                Smb2CreateRequest initialOpenRequest = firstClient.CreateCreateRequest(
                                    firstTreeId,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    requestedOplockLevel: Smb2OplockLevel.Batch,
                                    requestDurableHandle: true);
                                OpenCifsServerOperationResult<Smb2CreateResponse> initialOpenResult = firstHost.HandleCreate(firstSessionId, firstTreeId, initialOpenRequest);
                                OpenState durableOpen = firstClient.ApplyCreateResult(firstTreeId, "shared.txt", initialOpenResult.Status, initialOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2LockResponse> initialLockResult = firstHost.HandleLock(
                                    firstSessionId,
                                    firstTreeId,
                                    firstClient.CreateLockRequest(
                                        durableOpen.PersistentFileId,
                                        durableOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }));
                                firstClient.ApplyLockResult(durableOpen.PersistentFileId, durableOpen.VolatileFileId, initialLockResult.Status, initialLockResult.Response);

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                OpenCifsClientSession secondClient = CreateNegotiatedClient(secondHost);
                                uint secondTreeId = AuthenticateLoopbackSessionAndTree(secondHost, secondClient, credential);
                                ulong secondSessionId = secondClient.SessionId!.Value;

                                OpenCifsServerOperationResult<Smb2CreateResponse> competingOpenResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCreateRequest(
                                        secondTreeId,
                                        "shared.txt",
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState competingOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", competingOpenResult.Status, competingOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> detachedReadConflict = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateReadRequest(
                                        competingOpen.PersistentFileId,
                                        competingOpen.VolatileFileId,
                                        length: 4,
                                        offset: 0,
                                        minimumCount: 1));
                                TestAssertions.Equal(NtStatus.FileLockConflict, detachedReadConflict.Status, "Expected detached durable locks to block overlapping loopback reads.");

                                Smb2CreateRequest reconnectRequest = secondClient.CreateDurableReconnectCreateRequest(
                                    secondTreeId,
                                    "shared.txt",
                                    durableOpen.PersistentFileId,
                                    durableOpen.VolatileFileId,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    requestedOplockLevel: Smb2OplockLevel.Batch);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(secondSessionId, secondTreeId, reconnectRequest);
                                OpenState reconnectedOpen = secondClient.ApplyCreateResult(secondTreeId, "shared.txt", reconnectResult.Status, reconnectResult.Response);

                                OpenCifsServerOperationResult<Smb2LockResponse> reconnectedLockConflict = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateLockRequest(
                                        competingOpen.PersistentFileId,
                                        competingOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }));
                                TestAssertions.Equal(NtStatus.LockNotGranted, reconnectedLockConflict.Status, "Expected the reconnected durable open to restore its byte-range lock ownership.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateLockRequest(
                                        reconnectedOpen.PersistentFileId,
                                        reconnectedOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.Unlock
                                        }));
                                secondClient.ApplyLockResult(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId, unlockResult.Status, unlockResult.Response);

                                OpenCifsServerOperationResult<Smb2LockResponse> postUnlockLockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateLockRequest(
                                        competingOpen.PersistentFileId,
                                        competingOpen.VolatileFileId,
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }));
                                secondClient.ApplyLockResult(competingOpen.PersistentFileId, competingOpen.VolatileFileId, postUnlockLockResult.Status, postUnlockLockResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> competingCloseResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(competingOpen.PersistentFileId, competingOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(competingOpen.PersistentFileId, competingOpen.VolatileFileId, competingCloseResult.Status, competingCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> durableCloseResult = secondHost.HandleClose(
                                    secondSessionId,
                                    secondTreeId,
                                    secondClient.CreateCloseRequest(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId));
                                secondClient.ApplyCloseResult(reconnectedOpen.PersistentFileId, reconnectedOpen.VolatileFileId, durableCloseResult.Status, durableCloseResult.Response);
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }
    }
}
