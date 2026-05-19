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
    internal static class ServerFileIoValidationAndCallbackCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerRejectsUnsupportedPathsAndStaleHandles",
                        displayName: "Server rejects create collisions, missing files, path traversal, and stale handles",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "existing.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> collisionResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("existing.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, collisionResult.Status, "Expected create-new on an existing file to report a collision.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> missingOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("missing.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingOpenResult.Status, "Expected opening a missing file to fail.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> missingReadOnlyOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("missing-readonly.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingReadOnlyOpenResult.Status, "Expected read-only FILE_OPEN on a missing file to report STATUS_OBJECT_NAME_NOT_FOUND.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> traversalResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("..\\escape.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.ObjectPathNotFound, traversalResult.Status, "Expected path traversal outside the share root to be rejected.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> staleHandleResult = host.HandleFlush(
                                    sessionId,
                                    treeId,
                                    new Smb2FlushRequest
                                    {
                                        PersistentFileId = 999,
                                        VolatileFileId = 999
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, staleHandleResult.Status, "Expected stale file identifiers to be rejected.");
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
                        suiteId: "Server.FileIo",
                        caseId: "ServerRejectsInvalidSessionTreeAndOpenIdentifiersAcrossFileIoSurface",
                        displayName: "Server rejects invalid session, tree, and open identifiers across the bounded file-I/O surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerInvalidIds_" + Guid.NewGuid().ToString("N"));
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
                                    CreateFileCreateRequest("identifiers.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the invalid-identifier test open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateSessionResult = host.HandleCreate(
                                    sessionId + 1,
                                    treeId,
                                    CreateFileCreateRequest("other.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateSessionResult.Status, "Expected create requests with an unknown session identifier to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateTreeResult = host.HandleCreate(
                                    sessionId,
                                    treeId + 1,
                                    CreateFileCreateRequest("other.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateTreeResult.Status, "Expected create requests with an unknown tree identifier to be rejected.");

                                Smb2ReadRequest readRequest = new Smb2ReadRequest
                                {
                                    Length = 1,
                                    Offset = 0,
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId,
                                    MinimumCount = 0,
                                    Channel = 0,
                                    RemainingBytes = 0,
                                    ReadChannelInfo = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleRead(sessionId + 1, treeId, readRequest).Status, "Expected read requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleRead(sessionId, treeId + 1, readRequest).Status, "Expected read requests with an unknown tree identifier to be rejected.");

                                Smb2WriteRequest writeRequest = new Smb2WriteRequest
                                {
                                    Offset = 0,
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId,
                                    Channel = 0,
                                    RemainingBytes = 0,
                                    Flags = Smb2WriteFlags.None,
                                    DataBuffer = Encoding.UTF8.GetBytes("x"),
                                    WriteChannelInfo = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleWrite(sessionId + 1, treeId, writeRequest).Status, "Expected write requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleWrite(sessionId, treeId + 1, writeRequest).Status, "Expected write requests with an unknown tree identifier to be rejected.");

                                Smb2FlushRequest flushRequest = new Smb2FlushRequest
                                {
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleFlush(sessionId + 1, treeId, flushRequest).Status, "Expected flush requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleFlush(sessionId, treeId + 1, flushRequest).Status, "Expected flush requests with an unknown tree identifier to be rejected.");

                                Smb2LockRequest lockRequest = new Smb2LockRequest
                                {
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId,
                                    Locks = new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 1,
                                            Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                        }
                                    }
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleLock(sessionId + 1, treeId, lockRequest).Status, "Expected lock requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleLock(sessionId, treeId + 1, lockRequest).Status, "Expected lock requests with an unknown tree identifier to be rejected.");

                                Smb2CloseRequest closeRequest = new Smb2CloseRequest
                                {
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleClose(sessionId + 1, treeId, closeRequest).Status, "Expected close requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleClose(sessionId, treeId + 1, closeRequest).Status, "Expected close requests with an unknown tree identifier to be rejected.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> validCloseResult = host.HandleClose(sessionId, treeId, closeRequest);
                                TestAssertions.Equal(NtStatus.Success, validCloseResult.Status, "Expected the valid file-I/O test open to close cleanly.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerCreateCallbacksAllowSelectedPathsAndRejectBlockedCreates",
                        displayName: "Server create callbacks allow selected paths and reject blocked create requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsCreateCallbacks_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int createCallbackCount = 0;
                            string? lastCreatePath = null;

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(
                                    sharePath,
                                    new OpenCifsServerRequestCallbacks
                                    {
                                        CreateCallback = context =>
                                        {
                                            createCallbackCount++;
                                            lastCreatePath = context.FullPath;

                                            if (context.Request.Name.StartsWith("blocked", StringComparison.OrdinalIgnoreCase))
                                            {
                                                return NtStatus.AccessDenied;
                                            }

                                            return null;
                                        }
                                    });

                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);

                                ulong sessionId = treeContext.SessionId;

                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> allowedCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("allowed.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.Success, allowedCreateResult.Status, "Expected the create callback to allow selected create requests.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> allowedCloseResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = allowedCreateResult.Response.PersistentFileId,
                                        VolatileFileId = allowedCreateResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, allowedCloseResult.Status, "Expected the allowed create open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> blockedCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("blocked.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.AccessDenied, blockedCreateResult.Status, "Expected the create callback to reject blocked paths.");

                                TestAssertions.Equal(2, createCallbackCount, "Expected the create callback to run for both allowed and blocked requests.");
                                TestAssertions.Equal(Path.Combine(sharePath, "blocked.txt"), lastCreatePath, "Expected the create callback to observe the resolved blocked path.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "allowed.txt")), "Expected the allowed create path to reach the backing share.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "blocked.txt")), "Expected blocked create requests to leave no backing file.");
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

