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
    internal static class ClientConnectionDurabilityAndCompoundCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> BuildCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionReconnectsDurableBatchOpenAfterTransportDisconnect",
                        displayName: "Client connection reconnects a durable batch open after an ungraceful transport disconnect",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-client-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle firstTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle durableOpen = await client.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestDurableHandle: true).ConfigureAwait(false);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial direct-TCP open to be granted durable reconnect state.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the initial direct-TCP durable open to expose a reconnect token.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, durableOpen.OplockLevel, "Expected the initial durable direct-TCP open to receive a batch oplock.");
                                TestAssertions.True(durableOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 direct-TCP durable open to use durable-handle v2.");
                                TestAssertions.Equal(300000U, durableOpen.DurableTimeoutMs, "Expected the default SMB 3.0.2 direct-TCP durable open to preserve the bounded durable timeout.");
                                TestAssertions.False(durableOpen.IsPersistent, "Expected the default SMB 3.0.2 direct-TCP durable open to remain non-persistent.");

                                await client.SimulateTransportDisconnectAsync().ConfigureAwait(false);
                                TestAssertions.False(client.IsConnected, "Expected transport simulation to tear down the active direct-TCP connection.");
                                TestAssertions.True(durableOpen.IsClosed, "Expected the original durable open handle to be retired from active use after transport loss.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the durable open handle to remain usable as a reconnect token after transport loss.");

                                await Task.Delay(200, token).ConfigureAwait(false);
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await client.ReconnectDurableOpenAsync(secondTree, durableOpen, token).ConfigureAwait(false);

                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    durableOpen.VolatileFileId == reconnectedOpen.VolatileFileId,
                                    "Expected durable reconnect to allocate a new volatile file identifier.");
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected direct-TCP open to remain durable.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, reconnectedOpen.OplockLevel, "Expected durable reconnect to preserve the batch oplock.");
                                TestAssertions.True(reconnectedOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 direct-TCP durable reconnect to remain on durable-handle v2.");
                                TestAssertions.Equal(300000U, reconnectedOpen.DurableTimeoutMs, "Expected the default SMB 3.0.2 direct-TCP durable reconnect to preserve the bounded durable timeout.");
                                TestAssertions.False(durableOpen.CanReconnectDurably, "Expected the consumed reconnect token to be retired after successful durable reconnect.");

                                byte[] actualBytes = await client.ReadAsync(reconnectedOpen, 19, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal("durable-client-data", System.Text.Encoding.UTF8.GetString(actualBytes), "Expected durable reconnect to preserve file access over the new session.");

                                await client.CloseAsync(reconnectedOpen, cancellationToken: token).ConfigureAwait(false);
                                await client.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionReconnectsDurableLeaseOpenAfterTransportDisconnect",
                        displayName: "Client connection reconnects a durable lease-backed open after an ungraceful transport disconnect",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-client-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                byte[] leaseKey = Hex("0102030405060708090A0B0C0D0E0F10");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle firstTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle durableOpen = await client.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestDurableHandle: true,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey).ConfigureAwait(false);
                                TestAssertions.True(durableOpen.IsDurable, "Expected the initial direct-TCP lease-backed open to be granted durable reconnect state.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the initial direct-TCP durable lease open to expose a reconnect token.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, durableOpen.OplockLevel, "Expected the initial direct-TCP durable lease open to receive an SMB 2.1 lease.");
                                TestAssertions.SequenceEqual(leaseKey, durableOpen.LeaseKey, "Expected the direct-TCP durable lease open to preserve the requested lease key.");
                                TestAssertions.Equal(leaseState, durableOpen.LeaseState, "Expected the direct-TCP durable lease open to preserve the granted lease state.");

                                await client.SimulateTransportDisconnectAsync().ConfigureAwait(false);
                                TestAssertions.False(client.IsConnected, "Expected transport simulation to tear down the active direct-TCP connection.");
                                TestAssertions.True(durableOpen.IsClosed, "Expected the original durable lease open handle to be retired from active use after transport loss.");
                                TestAssertions.True(durableOpen.CanReconnectDurably, "Expected the durable lease open handle to remain usable as a reconnect token after transport loss.");

                                await Task.Delay(200, token).ConfigureAwait(false);
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await client.ReconnectDurableOpenAsync(secondTree, durableOpen, token).ConfigureAwait(false);

                                TestAssertions.Equal(durableOpen.PersistentFileId, reconnectedOpen.PersistentFileId, "Expected durable lease reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    durableOpen.VolatileFileId == reconnectedOpen.VolatileFileId,
                                    "Expected durable lease reconnect to allocate a new volatile file identifier.");
                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected direct-TCP lease-backed open to remain durable.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, reconnectedOpen.OplockLevel, "Expected durable lease reconnect to preserve the lease-backed oplock level.");
                                TestAssertions.SequenceEqual(leaseKey, reconnectedOpen.LeaseKey, "Expected durable lease reconnect to preserve the original lease key.");
                                TestAssertions.Equal(leaseState, reconnectedOpen.LeaseState, "Expected durable lease reconnect to preserve the granted lease state.");
                                TestAssertions.False(durableOpen.CanReconnectDurably, "Expected the consumed durable lease reconnect token to be retired after success.");

                                byte[] actualBytes = await client.ReadAsync(reconnectedOpen, 32, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal("durable-lease-client-data", System.Text.Encoding.UTF8.GetString(actualBytes), "Expected durable lease reconnect to preserve file access over the new session.");

                                await client.CloseAsync(reconnectedOpen, cancellationToken: token).ConfigureAwait(false);
                                await client.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionReconnectsDurableLeaseOpenWithDowngradedLeaseStateWhenACompetingOpenExists",
                        displayName: "Client connection reconnects a durable lease-backed open with a downgraded lease state when a competing open exists",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-client-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                byte[] leaseKey = Hex("1112131415161718191A1B1C1D1E1F20");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                await using OpenCifsClientConnection durableClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await using OpenCifsClientConnection competingClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle durableTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle durableOpen = await durableClient.OpenAsync(
                                    durableTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestedOplockLevel: Smb2OplockLevel.Lease,
                                    requestDurableHandle: true,
                                    requestedLeaseState: leaseState,
                                    leaseKey: leaseKey).ConfigureAwait(false);

                                await durableClient.SimulateTransportDisconnectAsync().ConfigureAwait(false);

                                await competingClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle competingTree = await competingClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle competingOpen = await competingClient.OpenAsync(
                                    competingTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle reconnectedTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await durableClient.ReconnectDurableOpenAsync(reconnectedTree, durableOpen, token).ConfigureAwait(false);

                                TestAssertions.True(reconnectedOpen.IsDurable, "Expected the reconnected direct-TCP lease-backed open to remain durable.");
                                TestAssertions.SequenceEqual(leaseKey, reconnectedOpen.LeaseKey, "Expected the reconnected direct-TCP lease-backed open to preserve its lease key.");
                                TestAssertions.Equal(Smb2LeaseState.None, reconnectedOpen.LeaseState, "Expected the competing open to downgrade the reconnected durable lease state to none.");

                                byte[] actualBytes = await durableClient.ReadAsync(reconnectedOpen, 32, 0, cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal("durable-lease-client-data", System.Text.Encoding.UTF8.GetString(actualBytes), "Expected the downgraded durable lease reconnect path to preserve file access.");

                                await competingClient.CloseAsync(competingOpen, cancellationToken: token).ConfigureAwait(false);
                                await competingClient.TreeDisconnectAsync(competingTree, token).ConfigureAwait(false);
                                await durableClient.CloseAsync(reconnectedOpen, cancellationToken: token).ConfigureAwait(false);
                                await durableClient.TreeDisconnectAsync(reconnectedTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionPreservesDurableByteRangeLocksAcrossTransportDisconnectAndReconnect",
                        displayName: "Client connection preserves durable byte-range locks across transport disconnect and reconnect",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-client-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection durableClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection competingClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle durableTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle durableOpen = await durableClient.OpenAsync(
                                    durableTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestDurableHandle: true).ConfigureAwait(false);
                                TestAssertions.True(durableOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 lock-carryover durable open to use durable-handle v2.");
                                TestAssertions.Equal(300000U, durableOpen.DurableTimeoutMs, "Expected the default SMB 3.0.2 lock-carryover durable open to preserve the bounded durable timeout.");
                                await durableClient.LockAsync(
                                    durableOpen,
                                    new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    },
                                    token).ConfigureAwait(false);

                                await durableClient.SimulateTransportDisconnectAsync().ConfigureAwait(false);

                                await competingClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle competingTree = await competingClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle competingOpen = await competingClient.OpenAsync(
                                    competingTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsStatusException detachedReadException;

                                try
                                {
                                    await competingClient.ReadAsync(competingOpen, 4, 0, cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected detached durable locks to block overlapping reads.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    detachedReadException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Read, detachedReadException.Command, "Expected detached durable lock conflicts to surface on the read command.");
                                TestAssertions.Equal(NtStatus.FileLockConflict, detachedReadException.Status, "Expected detached durable locks to block overlapping reads with STATUS_FILE_LOCK_CONFLICT.");

                                await durableClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle reconnectedTree = await durableClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle reconnectedOpen = await durableClient.ReconnectDurableOpenAsync(reconnectedTree, durableOpen, token).ConfigureAwait(false);
                                TestAssertions.True(reconnectedOpen.UsesDurableHandleV2, "Expected the default SMB 3.0.2 lock-carryover durable reconnect to remain on durable-handle v2.");

                                OpenCifsStatusException reconnectedLockException;

                                try
                                {
                                    await competingClient.LockAsync(
                                        competingOpen,
                                        new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        },
                                        token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected reconnected durable locks to remain enforced until the owner unlocks them.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    reconnectedLockException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Lock, reconnectedLockException.Command, "Expected the competing lock attempt to fail on the lock command.");
                                TestAssertions.Equal(NtStatus.LockNotGranted, reconnectedLockException.Status, "Expected the competing lock attempt to be rejected while the durable reconnect owner still holds the range.");

                                await durableClient.LockAsync(
                                    reconnectedOpen,
                                    new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.Unlock
                                        }
                                    },
                                    token).ConfigureAwait(false);

                                await competingClient.LockAsync(
                                    competingOpen,
                                    new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 4,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    },
                                    token).ConfigureAwait(false);

                                await competingClient.CloseAsync(competingOpen, cancellationToken: token).ConfigureAwait(false);
                                await competingClient.TreeDisconnectAsync(competingTree, token).ConfigureAwait(false);
                                await durableClient.CloseAsync(reconnectedOpen, cancellationToken: token).ConfigureAwait(false);
                                await durableClient.TreeDisconnectAsync(reconnectedTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionRejectsDurableReconnectForNonDurableHandles",
                        displayName: "Client connection rejects durable reconnect attempts for non-durable handles",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle firstTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle ordinaryOpen = await client.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.False(ordinaryOpen.IsDurable, "Expected a direct-TCP open without a durable request not to be reconnectable.");
                                TestAssertions.False(ordinaryOpen.CanReconnectDurably, "Expected a non-durable direct-TCP open not to expose a reconnect token.");

                                await client.SimulateTransportDisconnectAsync().ConfigureAwait(false);
                                await Task.Delay(200, token).ConfigureAwait(false);
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await client.TreeConnectAsync("public", token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<InvalidOperationException>(
                                    () => client.ReconnectDurableOpenAsync(secondTree, ordinaryOpen, token),
                                    "Expected durable reconnect to reject non-durable open handles.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesExclusiveOplockBreakOverDirectTcp",
                        displayName: "Client connection completes exclusive oplock-break handling over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection watcherClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection actorClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await watcherClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await actorClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle watcherTree = await watcherClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle actorTree = await actorClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle watcherOpen = await watcherClient.OpenAsync(
                                    watcherTree,
                                    "shared.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, watcherOpen.OplockLevel, "Expected the first direct-TCP open to receive an exclusive oplock grant.");

                                using CancellationTokenSource breakTokenSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                                breakTokenSource.CancelAfter(TimeSpan.FromSeconds(5));
                                Task<OpenCifsClientOplockBreakNotification> breakTask = watcherClient.WaitForOplockBreakAsync(breakTokenSource.Token);

                                await Task.Delay(100, token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle actorOpen = await actorClient.OpenAsync(
                                    actorTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);

                                OpenCifsClientOplockBreakNotification breakNotification = await breakTask.ConfigureAwait(false);
                                TestAssertions.Equal("public", breakNotification.ShareName, "Expected the oplock-break notification to retain the share name.");
                                TestAssertions.Equal("shared.txt", breakNotification.Path, "Expected the oplock-break notification to retain the normalized path.");
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, breakNotification.PreviousOplockLevel, "Expected the oplock-break notification to report the previous exclusive oplock.");
                                TestAssertions.Equal(Smb2OplockLevel.None, breakNotification.NewOplockLevel, "Expected the oplock-break notification to lower the oplock to none.");
                                TestAssertions.True(breakNotification.WasAcknowledged, "Expected exclusive oplock-break notifications to be acknowledged over direct TCP.");
                                TestAssertions.Equal(Smb2OplockLevel.None, watcherOpen.OplockLevel, "Expected the direct-TCP client open handle to adopt the lowered oplock level.");
                                TestAssertions.Equal(Smb2OplockLevel.None, actorOpen.OplockLevel, "Expected the conflicting second direct-TCP open not to receive an oplock grant.");

                                await actorClient.CloseAsync(actorOpen, cancellationToken: token).ConfigureAwait(false);
                                await watcherClient.CloseAsync(watcherOpen, cancellationToken: token).ConfigureAwait(false);
                                await actorClient.TreeDisconnectAsync(actorTree, token).ConfigureAwait(false);
                                await watcherClient.TreeDisconnectAsync(watcherTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionDoesNotGrantExclusiveOplockWhenFileAlreadyHasOpen",
                        displayName: "Client connection does not grant an exclusive oplock when the file already has an open",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection firstClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await using OpenCifsClientConnection secondClient = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port
                                });
                                await firstClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                await secondClient.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);

                                OpenCifsClientTreeHandle firstTree = await firstClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle secondTree = await secondClient.TreeConnectAsync("public", token).ConfigureAwait(false);
                                OpenCifsClientOpenHandle firstOpen = await firstClient.OpenAsync(
                                    firstTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.None, firstOpen.OplockLevel, "Expected the first direct-TCP open without an oplock request not to receive an oplock grant.");

                                OpenCifsClientOpenHandle secondOpen = await secondClient.OpenAsync(
                                    secondTree,
                                    "shared.txt",
                                    desiredAccess: 0x80000000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    cancellationToken: token,
                                    requestedOplockLevel: Smb2OplockLevel.Exclusive).ConfigureAwait(false);
                                TestAssertions.Equal(Smb2OplockLevel.None, secondOpen.OplockLevel, "Expected a direct-TCP exclusive oplock request to be denied while the file already has an open.");

                                await secondClient.CloseAsync(secondOpen, cancellationToken: token).ConfigureAwait(false);
                                await firstClient.CloseAsync(firstOpen, cancellationToken: token).ConfigureAwait(false);
                                await secondClient.TreeDisconnectAsync(secondTree, token).ConfigureAwait(false);
                                await firstClient.TreeDisconnectAsync(firstTree, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompletesRealisticCompoundCreateQueryReadWriteAndCloseFlows",
                        displayName: "Client connection completes realistic create-query-close, create-write-flush-close, and open-read-close compound flows over direct TCP",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);

                                byte[] expectedBytes = System.Text.Encoding.UTF8.GetBytes("compound-connection-data");
                                uint writtenCount = await client.CompoundCreateWriteFlushCloseAsync(
                                    treeHandle,
                                    "docs\\compound.txt",
                                    expectedBytes,
                                    createDisposition: Smb2CreateDisposition.OverwriteIf,
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.Equal((uint)expectedBytes.Length, writtenCount, "Expected the bounded compound write helper to acknowledge the full write length.");

                                FileAllInformation allInformation = FileAllInformation.ReadFrom(await client.CompoundCreateQueryInfoCloseAsync(
                                    treeHandle,
                                    "docs\\compound.txt",
                                    FileInformationClass.AllInformation,
                                    cancellationToken: token).ConfigureAwait(false));
                                TestAssertions.False(allInformation.StandardInformation.Directory, "Expected the bounded compound metadata helper to report a file.");
                                TestAssertions.Equal((ulong)expectedBytes.Length, allInformation.StandardInformation.EndOfFile, "Unexpected FILE_ALL_INFORMATION EOF after the bounded compound write helper.");
                                TestAssertions.Equal("docs\\compound.txt", allInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name after the bounded compound query helper.");

                                byte[] actualBytes = await client.CompoundOpenReadCloseAsync(
                                    treeHandle,
                                    "docs\\compound.txt",
                                    checked((uint)expectedBytes.Length),
                                    cancellationToken: token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, actualBytes, "Expected the bounded compound read helper to round-trip the file payload.");
                                TestAssertions.Equal(0, client.Session.OpenCount, "Expected bounded compound helpers to avoid leaking tracked opens on the client session.");

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                                TestAssertions.SequenceEqual(expectedBytes, File.ReadAllBytes(Path.Combine(sharePath, "docs", "compound.txt")), "Unexpected bytes persisted by the bounded compound helpers.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Connection",
                        caseId: "ClientConnectionCompoundHelpersPropagateCreateFailuresWithoutLeakingTrackedOpens",
                        displayName: "Client connection compound helpers propagate create failures and leave no tracked opens behind",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsClientConnection_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(sharePath, port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                await using OpenCifsClientConnection client = new OpenCifsClientConnection(new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    ServerPort = port,
                                    MinimumDialect = SmbDialect.Smb21,
                                    MaximumDialect = SmbDialect.Smb21
                                });
                                await client.ConnectAndAuthenticateAsync(CreateCredential(), token).ConfigureAwait(false);
                                OpenCifsClientTreeHandle treeHandle = await client.TreeConnectAsync("public", token).ConfigureAwait(false);

                                OpenCifsStatusException missingReadException;

                                try
                                {
                                    await client.CompoundOpenReadCloseAsync(treeHandle, "missing.txt", 8, cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected compound open-read-close to fail for a missing path.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    missingReadException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Create, missingReadException.Command, "Expected missing-path compound reads to surface the create failure.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingReadException.Status, "Expected missing-path compound reads to report STATUS_OBJECT_NAME_NOT_FOUND.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingReadException.Category, "Expected missing-path compound reads to normalize to NotFound.");
                                TestAssertions.Equal(0, client.Session.OpenCount, "Expected failed bounded compound reads not to leak tracked opens.");

                                OpenCifsStatusException missingQueryException;

                                try
                                {
                                    await client.CompoundCreateQueryInfoCloseAsync(treeHandle, "missing.txt", FileInformationClass.AllInformation, cancellationToken: token).ConfigureAwait(false);
                                    throw new InvalidOperationException("Expected compound create-query-close to fail for a missing path.");
                                }
                                catch (OpenCifsStatusException exception)
                                {
                                    missingQueryException = exception;
                                }

                                TestAssertions.Equal(Smb2Command.Create, missingQueryException.Command, "Expected missing-path compound metadata queries to surface the create failure.");
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingQueryException.Status, "Expected missing-path compound metadata queries to report STATUS_OBJECT_NAME_NOT_FOUND.");
                                TestAssertions.Equal(OpenCifsErrorCategory.NotFound, missingQueryException.Category, "Expected missing-path compound metadata queries to normalize to NotFound.");
                                TestAssertions.Equal(0, client.Session.OpenCount, "Expected failed bounded compound metadata queries not to leak tracked opens.");

                                await client.TreeDisconnectAsync(treeHandle, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }
                        })
            };
        }
    }
}
