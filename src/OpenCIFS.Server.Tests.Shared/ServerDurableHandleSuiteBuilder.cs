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
    internal static class ServerDurableHandleSuiteBuilder
    {
        internal static TestSuiteDescriptor ServerDurableHandleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Durable",
                displayName: "Server durable-handle reconnect handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerDetachesDurableBatchOpenAcrossTransportDisconnectAndReconnectsIt",
                        displayName: "Server detaches a durable batch open across transport disconnect and reconnects it on a new session and tree",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(firstHost);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableCreateRequest("shared.txt"));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, firstOpen.Response.OplockLevel, "Expected the initial durable open to receive a batch oplock.");
                                TestAssertions.Equal(1, Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts).Length, "Expected the initial durable open to return a durable response context.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(secondHost);

                                ulong secondSessionId = secondTreeContext.SessionId;

                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the durable reconnect to succeed on a new session and tree.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, reconnectResult.Response.PersistentFileId, "Expected durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    reconnectResult.Response.VolatileFileId == firstOpen.Response.VolatileFileId,
                                    "Expected durable reconnect to allocate a new volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, reconnectResult.Response.OplockLevel, "Expected durable reconnect to preserve the granted batch oplock.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2ReadRequest
                                    {
                                        PersistentFileId = reconnectResult.Response.PersistentFileId,
                                        VolatileFileId = reconnectResult.Response.VolatileFileId,
                                        Length = 12,
                                        Offset = 0,
                                        MinimumCount = 1
                                    });
                                TestAssertions.Equal(NtStatus.Success, readResult.Status, "Expected durable reconnect reads to succeed.");
                                TestAssertions.Equal("durable-data", Encoding.UTF8.GetString(readResult.Response.DataBuffer), "Expected the reconnected durable open to preserve file access.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = reconnectResult.Response.PersistentFileId,
                                            VolatileFileId = reconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the reconnected durable open to close cleanly.");
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
                        suiteId: "Server.Durable",
                        caseId: "ServerDetachesDurableLeaseOpenAcrossTransportDisconnectAndReconnectsIt",
                        displayName: "Server detaches a durable lease-backed open across transport disconnect and reconnects it on a new session and tree",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurableLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                Guid durableClientGuid = Guid.NewGuid();
                                byte[] leaseKey = Hex("0102030405060708090A0B0C0D0E0F10");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                NegotiateDialect(firstHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(firstHost);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableLeaseCreateRequest("shared.txt", leaseKey, leaseState));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable lease-backed open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, firstOpen.Response.OplockLevel, "Expected the initial durable lease-backed open to receive an SMB 2.1 lease.");
                                Smb2CreateContext[] initialCreateContexts = Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts);
                                TestAssertions.Equal(2, initialCreateContexts.Length, "Expected the initial durable lease-backed open to return both durable and lease response contexts.");
                                TestAssertions.True(Smb2DurableHandleResponseContext.IsMatch(initialCreateContexts[0]), "Expected the first create response context to advertise durable reconnect state.");
                                Smb2CreateResponseLeaseContext initialLeaseResponse = Smb2CreateResponseLeaseContext.ReadFrom(initialCreateContexts[1]);
                                TestAssertions.SequenceEqual(leaseKey, initialLeaseResponse.LeaseKey, "Expected the initial durable lease response to preserve the lease key.");
                                TestAssertions.Equal(leaseState, initialLeaseResponse.LeaseState, "Expected the initial durable lease response to preserve the granted lease state.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                NegotiateDialect(secondHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(secondHost);
                                ulong secondSessionId = secondTreeContext.SessionId;
                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableLeaseReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        leaseKey,
                                        leaseState));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the durable lease reconnect to succeed on a new session and tree.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, reconnectResult.Response.PersistentFileId, "Expected durable lease reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    reconnectResult.Response.VolatileFileId == firstOpen.Response.VolatileFileId,
                                    "Expected durable lease reconnect to allocate a new volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, reconnectResult.Response.OplockLevel, "Expected durable lease reconnect to preserve the lease-backed oplock level.");
                                Smb2CreateContext[] reconnectCreateContexts = Smb2CreateContextCodec.Decode(reconnectResult.Response.CreateContexts);
                                TestAssertions.Equal(2, reconnectCreateContexts.Length, "Expected the durable lease reconnect response to return both durable and lease contexts.");
                                TestAssertions.True(Smb2DurableHandleResponseContext.IsMatch(reconnectCreateContexts[0]), "Expected the reconnect response to retain durable reconnect state.");
                                Smb2CreateResponseLeaseContext reconnectLeaseResponse = Smb2CreateResponseLeaseContext.ReadFrom(reconnectCreateContexts[1]);
                                TestAssertions.SequenceEqual(leaseKey, reconnectLeaseResponse.LeaseKey, "Expected the reconnect lease response to preserve the original lease key.");
                                TestAssertions.Equal(leaseState, reconnectLeaseResponse.LeaseState, "Expected the reconnect lease response to preserve the granted lease state.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2ReadRequest
                                    {
                                        PersistentFileId = reconnectResult.Response.PersistentFileId,
                                        VolatileFileId = reconnectResult.Response.VolatileFileId,
                                        Length = 32,
                                        Offset = 0,
                                        MinimumCount = 1
                                    });
                                TestAssertions.Equal(NtStatus.Success, readResult.Status, "Expected durable lease reconnect reads to succeed.");
                                TestAssertions.Equal("durable-lease-data", Encoding.UTF8.GetString(readResult.Response.DataBuffer), "Expected the reconnected durable lease open to preserve file access.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = reconnectResult.Response.PersistentFileId,
                                            VolatileFileId = reconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the reconnected durable lease open to close cleanly.");
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
                        suiteId: "Server.Durable",
                        caseId: "ServerDetachesSmb302DurableHandleV2BatchOpenAcrossTransportDisconnectAndReconnectsIt",
                        displayName: "Server detaches an SMB 3.0.2 durable-handle v2 batch open across transport disconnect and reconnects it on a new session and tree",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurableV2_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-v2-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName,
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = false
                            }, sharedState);
                            OpenCifsServerHost secondHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName,
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = false
                            }, sharedState);
                            RegisterDefaultShareAndAccount(firstHost, sharePath);
                            RegisterDefaultShareAndAccount(secondHost, sharePath);

                            try
                            {
                                Guid clientGuid = Guid.NewGuid();
                                Guid createGuid = Guid.NewGuid();
                                NegotiateDialect(firstHost, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302, clientGuid);
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(firstHost);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableHandleV2CreateRequest("shared.txt", createGuid));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial SMB 3.0.2 durable-handle v2 open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, firstOpen.Response.OplockLevel, "Expected the initial SMB 3.0.2 durable-handle v2 open to receive a batch oplock.");
                                Smb2CreateContext[] initialCreateContexts = Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts);
                                TestAssertions.Equal(1, initialCreateContexts.Length, "Expected the initial SMB 3.0.2 durable-handle v2 open to return a single durable response context.");
                                TestAssertions.True(Smb2DurableHandleResponseV2Context.IsMatch(initialCreateContexts[0]), "Expected the initial SMB 3.0.2 durable open to return a durable-handle v2 response context.");
                                Smb2DurableHandleResponseV2Context initialDurableResponse = Smb2DurableHandleResponseV2Context.ReadFrom(initialCreateContexts[0]);
                                TestAssertions.Equal(300000U, initialDurableResponse.Timeout, "Expected the bounded SMB 3.0.2 durable-handle v2 timeout to clamp to the managed default.");
                                TestAssertions.Equal(Smb2DurableHandleFlags.None, initialDurableResponse.Flags, "Expected the bounded SMB 3.0.2 durable-handle v2 response to stay non-persistent.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                NegotiateDialect(secondHost, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302, clientGuid);
                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(secondHost);
                                ulong secondSessionId = secondTreeContext.SessionId;
                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableHandleV2ReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        createGuid));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the SMB 3.0.2 durable-handle v2 reconnect to succeed on a new session and tree.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, reconnectResult.Response.PersistentFileId, "Expected SMB 3.0.2 durable-handle v2 reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(reconnectResult.Response.VolatileFileId == firstOpen.Response.VolatileFileId, "Expected SMB 3.0.2 durable-handle v2 reconnect to allocate a new volatile file identifier.");
                                Smb2CreateContext[] reconnectCreateContexts = Smb2CreateContextCodec.Decode(reconnectResult.Response.CreateContexts);
                                TestAssertions.Equal(1, reconnectCreateContexts.Length, "Expected the SMB 3.0.2 durable-handle v2 reconnect to return a single durable response context.");
                                TestAssertions.True(Smb2DurableHandleResponseV2Context.IsMatch(reconnectCreateContexts[0]), "Expected the SMB 3.0.2 durable-handle v2 reconnect response to retain a durable-handle v2 response context.");
                                Smb2DurableHandleResponseV2Context reconnectDurableResponse = Smb2DurableHandleResponseV2Context.ReadFrom(reconnectCreateContexts[0]);
                                TestAssertions.Equal(300000U, reconnectDurableResponse.Timeout, "Expected SMB 3.0.2 durable-handle v2 reconnect to preserve the bounded durable timeout.");
                                TestAssertions.Equal(Smb2DurableHandleFlags.None, reconnectDurableResponse.Flags, "Expected SMB 3.0.2 durable-handle v2 reconnect to stay non-persistent.");
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
                        suiteId: "Server.Durable",
                        caseId: "ServerRejectsPersistentDurableHandleV2HintsInBoundedSmb302Slice",
                        displayName: "Server rejects persistent durable-handle v2 hints in the bounded SMB 3.0.2 slice",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurablePersistent_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");

                            try
                            {
                                OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                                {
                                    ServerName = TestEnvironmentDefaults.DefaultServerName,
                                    MinimumDialect = SmbDialect.Smb302,
                                    MaximumDialect = SmbDialect.Smb302,
                                    RequireEncryptionForSmb3 = false
                                });
                                RegisterDefaultShareAndAccount(host, sharePath);
                                NegotiateDialect(host, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateDurableHandleV2CreateRequest(
                                        "shared.txt",
                                        Guid.NewGuid(),
                                        flags: Smb2DurableHandleFlags.Persistent));
                                TestAssertions.Equal(NtStatus.InvalidParameter, createResult.Status, "Expected the bounded SMB 3.0.2 slice to reject persistent durable-handle v2 hints.");
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
                        suiteId: "Server.Durable",
                        caseId: "ServerRejectsMismatchedDurableReconnectAndKeepsTheDetachedOpenAvailable",
                        displayName: "Server rejects mismatched durable reconnect paths and keeps the detached open available for the correct reconnect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(firstHost);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableCreateRequest("shared.txt"));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable open to succeed.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(secondHost);

                                ulong secondSessionId = secondTreeContext.SessionId;

                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "wrong.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidReconnectResult.Status, "Expected reconnects with the wrong path to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.Success, validReconnectResult.Status, "Expected the detached durable open to remain reconnectable after a rejected mismatched reconnect.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = validReconnectResult.Response.PersistentFileId,
                                            VolatileFileId = validReconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the successfully reconnected durable open to close cleanly.");
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
                        suiteId: "Server.Durable",
                        caseId: "ServerRejectsMissingOrMismatchedLeaseContextDuringDurableReconnectAndKeepsTheDetachedOpenAvailable",
                        displayName: "Server rejects missing or mismatched lease reconnect state and keeps the detached durable open available for the correct retry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurableLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                Guid durableClientGuid = Guid.NewGuid();
                                byte[] leaseKey = Hex("1112131415161718191A1B1C1D1E1F20");
                                byte[] wrongLeaseKey = Hex("2122232425262728292A2B2C2D2E2F30");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                NegotiateDialect(firstHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(firstHost);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableLeaseCreateRequest("shared.txt", leaseKey, leaseState));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable lease-backed open to succeed.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                NegotiateDialect(secondHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(secondHost);
                                ulong secondSessionId = secondTreeContext.SessionId;
                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> missingLeaseReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingLeaseReconnectResult.Status, "Expected durable lease reconnect requests without a lease create context to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> wrongLeaseReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableLeaseReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        wrongLeaseKey,
                                        leaseState));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, wrongLeaseReconnectResult.Status, "Expected durable lease reconnect requests with the wrong lease key to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableLeaseReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        leaseKey,
                                        leaseState));
                                TestAssertions.Equal(NtStatus.Success, validReconnectResult.Status, "Expected the detached durable lease open to remain reconnectable after rejected retries.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = validReconnectResult.Response.PersistentFileId,
                                            VolatileFileId = validReconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the successfully reconnected durable lease open to close cleanly.");
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
                        suiteId: "Server.Durable",
                        caseId: "ServerPreservesDurableByteRangeLocksAcrossTransportDisconnectAndReconnect",
                        displayName: "Server preserves durable byte-range locks across transport disconnect and reconnect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                AuthenticatedTreeContext firstTreeContext = AuthenticateAndConnectTree(firstHost);
                                ulong firstSessionId = firstTreeContext.SessionId;
                                uint firstTreeId = firstTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableCreateRequest("shared.txt"));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> initialLockResult = firstHost.HandleLock(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, initialLockResult.Status, "Expected the durable open to acquire its initial exclusive byte-range lock.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                AuthenticatedTreeContext secondTreeContext = AuthenticateAndConnectTree(secondHost);

                                ulong secondSessionId = secondTreeContext.SessionId;

                                uint secondTreeId = secondTreeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the competing open to succeed while the durable handle is detached.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> detachedReadConflict = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2ReadRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Length = 4,
                                        Offset = 0,
                                        MinimumCount = 1
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, detachedReadConflict.Status, "Expected detached durable locks to block overlapping reads.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the durable reconnect to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> reconnectedLockConflict = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.LockNotGranted, reconnectedLockConflict.Status, "Expected the reconnected durable open to restore its exclusive byte-range lock ownership.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = reconnectResult.Response.PersistentFileId,
                                        VolatileFileId = reconnectResult.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, unlockResult.Status, "Expected the reconnected durable open to unlock its restored byte-range lock.");

                                OpenCifsServerOperationResult<Smb2LockResponse> postUnlockLockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, postUnlockLockResult.Status, "Expected competing opens to acquire the range after the durable reconnect path unlocks it.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the competing open to close cleanly.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = reconnectResult.Response.PersistentFileId,
                                            VolatileFileId = reconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the reconnected durable open to close cleanly.");
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
