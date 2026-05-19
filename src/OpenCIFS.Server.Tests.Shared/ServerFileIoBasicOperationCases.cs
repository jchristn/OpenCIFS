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
    internal static class ServerFileIoBasicOperationCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerHandlesCreateWriteFlushReadAndClose",
                        displayName: "Server handles create, write, flush, read, and close against the configured share path",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                Smb2CreateRequest createRequest = CreateFileCreateRequest("notes.txt", Smb2CreateDisposition.OpenIf);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(sessionId, treeId, createRequest);

                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected file create to succeed.");
                                TestAssertions.True(createResult.Response.PersistentFileId != 0, "Expected the server to allocate a persistent file identifier.");

                                byte[] payload = Encoding.UTF8.GetBytes("hello file io");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
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
                                    });
                                TestAssertions.Equal(NtStatus.Success, writeResult.Status, "Expected file write to succeed.");
                                TestAssertions.Equal((uint)payload.Length, writeResult.Response.Count, "Unexpected server write count.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = host.HandleFlush(
                                    sessionId,
                                    treeId,
                                    new Smb2FlushRequest
                                    {
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, flushResult.Status, "Expected file flush to succeed.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = (uint)payload.Length,
                                        Offset = 0,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        MinimumCount = (uint)payload.Length,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, readResult.Status, "Expected file read to succeed.");
                                TestAssertions.SequenceEqual(payload, readResult.Response.DataBuffer, "Unexpected bytes returned by the server read path.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        Flags = Smb2CloseFlags.PostQueryAttributes,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected file close to succeed.");
                                TestAssertions.Equal((ulong)payload.Length, closeResult.Response.EndOfFile, "Unexpected close-response EOF size.");

                                byte[] storedBytes = File.ReadAllBytes(Path.Combine(sharePath, "notes.txt"));
                                TestAssertions.SequenceEqual(payload, storedBytes, "Unexpected bytes persisted to the backing share path.");
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
                        caseId: "ServerToleratesSmb3CreateHintContextsOnFreshOpen",
                        displayName: "Server tolerates SMB 3.x durable and lease create hints on a fresh open without claiming the advanced features",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                                {
                                    ServerName = TestEnvironmentDefaults.DefaultServerName,
                                    MinimumDialect = SmbDialect.Smb302,
                                    MaximumDialect = SmbDialect.Smb302,
                                    RequireEncryptionForSmb3 = true
                                });
                                host.RegisterShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = TestEnvironmentDefaults.DefaultShareName,
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                });
                                host.RegisterAccount(new OpenCifsServerAccount
                                {
                                    UserName = TestEnvironmentDefaults.DefaultUserName,
                                    UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                                    Password = TestEnvironmentDefaults.DefaultPassword
                                });
                                NegotiateDialect(host, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                Smb2CreateRequest createRequest = new Smb2CreateRequest
                                {
                                    RequestedOplockLevel = Smb2OplockLevel.None,
                                    ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                    DesiredAccess = 0x00100081U,
                                    FileAttributes = ProtocolFileAttributes.Directory,
                                    ShareAccess = 0x00000003U,
                                    CreateDisposition = Smb2CreateDisposition.Create,
                                    CreateOptions = Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.OpenReparsePoint,
                                    Name = "native-dir",
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2DurableHandleRequestV2Context
                                        {
                                            Timeout = 0,
                                            Flags = Smb2DurableHandleFlags.None,
                                            CreateGuid = Guid.NewGuid()
                                        }.ToCreateContext(),
                                        new Smb2CreateRequestLeaseContext
                                        {
                                            LeaseKey = new byte[16],
                                            LeaseState = Smb2LeaseState.ReadCaching
                                        }.ToCreateContext()
                                    })
                                };

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(sessionId, treeId, createRequest);

                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the server to tolerate bounded SMB 3.x create hints on a fresh open.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "native-dir")), "Expected the server to still materialize the requested directory.");
                                TestAssertions.Equal(0, createResult.Response.CreateContexts.Length, "Expected the bounded server path to tolerate but not advertise durable-handle v2 or lease-v2 response contexts.");
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

