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

    internal static class ClientLockingSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Locking",
                displayName: "Client byte-range locking",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Locking",
                        caseId: "ClientBuildsLockRequestsAndAcceptsSuccessfulResponses",
                        displayName: "Client builds SMB2 lock requests and accepts successful lock and unlock responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
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
                                    PersistentFileId = 610,
                                    VolatileFileId = 611,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2LockRequest lockRequest = session.CreateLockRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new Smb2LockElement
                                {
                                    Offset = 32,
                                    Length = 8,
                                    Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                });
                            TestAssertions.Equal(1, lockRequest.Locks.Length, "Expected a single client lock element.");
                            TestAssertions.Equal(32UL, lockRequest.Locks[0].Offset, "Unexpected client lock offset.");
                            TestAssertions.Equal(8UL, lockRequest.Locks[0].Length, "Unexpected client lock length.");
                            TestAssertions.Equal(
                                Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately,
                                lockRequest.Locks[0].Flags,
                                "Unexpected client lock flags.");
                            session.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2LockResponse());

                            Smb2LockRequest unlockRequest = session.CreateLockRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                new Smb2LockElement
                                {
                                    Offset = 32,
                                    Length = 8,
                                    Flags = Smb2LockFlags.Unlock
                                });
                            TestAssertions.Equal(Smb2LockFlags.Unlock, unlockRequest.Locks[0].Flags, "Unexpected client unlock flags.");
                            session.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.Success, new Smb2LockResponse());
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Locking",
                        caseId: "ClientRejectsLockRequestsForUnknownOpenOrFailedStatus",
                        displayName: "Client rejects lock requests for unknown opens and throws on failed lock responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateLockRequest(
                                    1,
                                    2,
                                    new Smb2LockElement
                                    {
                                        Offset = 0,
                                        Length = 1,
                                        Flags = Smb2LockFlags.ExclusiveLock
                                    }),
                                "Lock requests should fail for an unknown open.");

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
                                    PersistentFileId = 620,
                                    VolatileFileId = 621,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyLockResult(openState.PersistentFileId, openState.VolatileFileId, NtStatus.LockNotGranted, new Smb2LockResponse()),
                                "Failed lock results should throw.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
