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
    internal static class ServerLockingSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Locking",
                displayName: "Server byte-range locking",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Locking",
                        caseId: "ServerAppliesByteRangeLocksAndReleasesThemOnUnlockOrClose",
                        displayName: "Server applies bounded byte-range locks and rejects conflicting lock, read, and write operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "locked.txt"), "0123456789");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("locked.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U, shareAccess: 0x00000007U));
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("locked.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first locking test open to succeed.");
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the second locking test open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> exclusiveLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 2,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, exclusiveLockResult.Status, "Expected the first exclusive byte-range lock to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> conflictingLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 2,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.LockNotGranted, conflictingLockResult.Status, "Expected conflicting exclusive byte-range locks to fail.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> conflictingReadResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = 2,
                                        Offset = 2,
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        MinimumCount = 0,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, conflictingReadResult.Status, "Expected reads through a competing open to fail inside an exclusive byte-range lock.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> conflictingWriteResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 2,
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = Encoding.UTF8.GetBytes("XX"),
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, conflictingWriteResult.Status, "Expected writes through a competing open to fail inside an exclusive byte-range lock.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 2,
                                                Length = 4,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, unlockResult.Status, "Expected unlocking a previously locked byte range to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> sharedLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.SharedLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, sharedLockResult.Status, "Expected the first shared byte-range lock to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> secondSharedLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.SharedLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondSharedLockResult.Status, "Expected overlapping shared byte-range locks across opens to succeed.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> sharedWriteConflictResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 0,
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = Encoding.UTF8.GetBytes("YY"),
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, sharedWriteConflictResult.Status, "Expected shared byte-range locks to block writes across opens.");

                                OpenCifsServerOperationResult<Smb2LockResponse> secondSharedUnlockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondSharedUnlockResult.Status, "Expected the second shared byte-range lock to unlock cleanly.");

                                OpenCifsServerOperationResult<Smb2LockResponse> closeCleanupLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 6,
                                                Length = 2,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeCleanupLockResult.Status, "Expected a second exclusive byte-range lock to succeed before close cleanup.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> firstClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstClose.Status, "Expected the first locking test open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2LockResponse> postCloseLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 6,
                                                Length = 2,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, postCloseLockResult.Status, "Expected closing an open to release its outstanding byte-range locks.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> secondClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondClose.Status, "Expected the second locking test open to close cleanly.");
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
                        suiteId: "Server.Locking",
                        caseId: "ServerRejectsInvalidLockTargetsAndUnlockMisses",
                        displayName: "Server rejects directory locks, stale handles, and unlocks for ranges that are not held",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "locked.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("locked.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpen.Status, "Expected the lock-validation file open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockMissResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.RangeNotLocked, unlockMissResult.Status, "Expected unlocking an unheld byte range to fail.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the directory locking test open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> directoryLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 1,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, directoryLockResult.Status, "Expected directory handles to reject byte-range locking.");

                                OpenCifsServerOperationResult<Smb2LockResponse> staleHandleResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = 999,
                                        VolatileFileId = 999,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 1,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, staleHandleResult.Status, "Expected stale lock handles to be rejected.");
                            }
                            finally
                            {
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
