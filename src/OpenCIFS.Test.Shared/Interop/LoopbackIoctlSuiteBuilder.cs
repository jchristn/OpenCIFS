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
    internal static class LoopbackIoctlSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackIoctl",
                displayName: "Loopback IOCTL coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackIoctl",
                        caseId: "ClientAndServerTransceiveManagedNamedPipeEchoEndpointThroughIpcWithHeaders",
                        displayName: "Client and server loopback transceive a managed named-pipe echo endpoint through IPC$ with headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            server.RegisterNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoints.CreateUtf8EchoEndpoint());
                            OpenCifsClientSession client = CreateClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 4);

                            Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
                            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest("IPC$");
                            server.ValidateAndAcceptRequestHeader(treeConnectHeader, Smb2Command.TreeConnect, expectedSessionId: sessionId);
                            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(sessionId, treeConnectRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(treeConnectHeader, treeConnectResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                            client.ApplyTreeConnectResult("IPC$", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

                            Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeConnectResult.TreeId, sessionId: sessionId);
                            Smb2CreateRequest createRequest = client.CreateCreateRequest(treeConnectResult.TreeId, OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName);
                            server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                            OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeConnectResult.TreeId, createRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                            OpenState pipeOpen = client.ApplyCreateResult(treeConnectResult.TreeId, OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName, createResult.Status, createResult.Response);

                            byte[] payload = Encoding.UTF8.GetBytes("loopback pipe");
                            Smb2Header ioctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeConnectResult.TreeId, sessionId: sessionId);
                            Smb2IoctlRequest ioctlRequest = client.CreateIoctlRequest(
                                pipeOpen.PersistentFileId,
                                pipeOpen.VolatileFileId,
                                (uint)FsctlCode.PipeTransceive,
                                payload,
                                maxOutputResponse: 4096,
                                maxInputResponse: 0,
                                flags: Smb2IoctlFlags.IsFsctl);
                            server.ValidateAndAcceptRequestHeader(ioctlHeader, Smb2Command.Ioctl, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                            OpenCifsServerOperationResult<Smb2IoctlResponse> ioctlResult = server.HandleIoctl(sessionId, treeConnectResult.TreeId, ioctlRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(ioctlHeader, ioctlResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                            byte[] echoedBytes = client.ApplyIoctlResult(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId, ioctlResult.Status, ioctlResult.Response);

                            Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeConnectResult.TreeId, sessionId: sessionId);
                            Smb2CloseRequest closeRequest = client.CreateCloseRequest(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId);
                            server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                            OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(sessionId, treeConnectResult.TreeId, closeRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                            client.ApplyCloseResult(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId, closeResult.Status, closeResult.Response);

                            TestAssertions.SequenceEqual(payload, echoedBytes, "Expected loopback named-pipe IOCTL coverage to return the original UTF-8 payload.");
                            TestAssertions.Equal(0, client.OpenCount, "Expected the loopback named-pipe close path to clear the tracked pipe open.");
                            TestAssertions.Equal(4, client.AvailableCredits, "Expected the loopback named-pipe IOCTL coverage to preserve the negotiated client credit window.");
                            TestAssertions.Equal(4, server.AvailableCredits, "Expected the loopback named-pipe IOCTL coverage to preserve the negotiated server credit window.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackIoctl",
                        caseId: "ClientAndServerQueryManagedShareInfoThroughIpcAndSrvsvcWithHeaders",
                        displayName: "Client and server loopback query managed share info through IPC$ and srvsvc with headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSrvsvc_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                server.RegisterNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoints.CreateSrvsvcShareEnumerationEndpoint());
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 4);

                                Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
                                Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest("IPC$");
                                server.ValidateAndAcceptRequestHeader(treeConnectHeader, Smb2Command.TreeConnect, expectedSessionId: sessionId);
                                OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(sessionId, treeConnectRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(treeConnectHeader, treeConnectResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                                client.ApplyTreeConnectResult("IPC$", treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeConnectResult.TreeId, sessionId: sessionId);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeConnectResult.TreeId, "srvsvc");
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(sessionId, treeConnectResult.TreeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                                OpenState pipeOpen = client.ApplyCreateResult(treeConnectResult.TreeId, "srvsvc", createResult.Status, createResult.Response);

                                DceRpcBindRequest bindRequest = new DceRpcBindRequest
                                {
                                    CallId = 1
                                };
                                Smb2Header bindIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeConnectResult.TreeId, sessionId: sessionId);
                                Smb2IoctlRequest bindIoctlRequest = client.CreateIoctlRequest(
                                    pipeOpen.PersistentFileId,
                                    pipeOpen.VolatileFileId,
                                    (uint)FsctlCode.PipeTransceive,
                                    bindRequest.ToByteArray(),
                                    maxOutputResponse: 4096,
                                    maxInputResponse: 0,
                                    flags: Smb2IoctlFlags.IsFsctl);
                                server.ValidateAndAcceptRequestHeader(bindIoctlHeader, Smb2Command.Ioctl, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> bindIoctlResult = server.HandleIoctl(sessionId, treeConnectResult.TreeId, bindIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(bindIoctlHeader, bindIoctlResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                                byte[] bindResponseBytes = client.ApplyIoctlResult(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId, bindIoctlResult.Status, bindIoctlResult.Response);
                                DceRpcBindAck bindAck = DceRpcBindAck.ReadFrom(bindResponseBytes);
                                bindAck.EnsureAccepted();

                                SrvsvcNetrShareGetInfoRequest shareInfoRequest = new SrvsvcNetrShareGetInfoRequest
                                {
                                    ShareName = TestEnvironmentDefaults.DefaultShareName
                                };
                                DceRpcRequestPdu rpcRequest = new DceRpcRequestPdu
                                {
                                    CallId = 2,
                                    ContextId = DceRpcConstants.SrvsvcContextId,
                                    OperationNumber = SrvsvcNetrShareGetInfoRequest.OperationNumber,
                                    StubData = shareInfoRequest.ToByteArray()
                                };
                                Smb2Header ioctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeConnectResult.TreeId, sessionId: sessionId);
                                Smb2IoctlRequest ioctlRequest = client.CreateIoctlRequest(
                                    pipeOpen.PersistentFileId,
                                    pipeOpen.VolatileFileId,
                                    (uint)FsctlCode.PipeTransceive,
                                    rpcRequest.ToByteArray(),
                                    maxOutputResponse: 4096,
                                    maxInputResponse: 0,
                                    flags: Smb2IoctlFlags.IsFsctl);
                                server.ValidateAndAcceptRequestHeader(ioctlHeader, Smb2Command.Ioctl, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> ioctlResult = server.HandleIoctl(sessionId, treeConnectResult.TreeId, ioctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(ioctlHeader, ioctlResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                                byte[] rpcResponseBytes = client.ApplyIoctlResult(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId, ioctlResult.Status, ioctlResult.Response);
                                DceRpcResponsePdu rpcResponse = DceRpcResponsePdu.ReadFrom(rpcResponseBytes);
                                SrvsvcNetrShareGetInfoResponse shareInfoResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(rpcResponse.StubData);

                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeConnectResult.TreeId, sessionId: sessionId);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: sessionId, expectedTreeId: treeConnectResult.TreeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(sessionId, treeConnectResult.TreeId, closeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
                                client.ApplyCloseResult(pipeOpen.PersistentFileId, pipeOpen.VolatileFileId, closeResult.Status, closeResult.Response);

                                TestAssertions.Equal((uint)0, shareInfoResponse.ReturnCode, "Expected loopback SRVSVC share-info queries to succeed.");
                                TestAssertions.True(shareInfoResponse.Share != null, "Expected loopback SRVSVC share-info queries to return share details.");
                                TestAssertions.Equal(TestEnvironmentDefaults.DefaultShareName, shareInfoResponse.Share!.Name, "Unexpected loopback SRVSVC share-info share name.");
                                TestAssertions.Equal(sharePath, shareInfoResponse.Share.Path, "Unexpected loopback SRVSVC share-info local path.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback SRVSVC share-info close path to clear the tracked pipe open.");
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
                        suiteId: "Interop.LoopbackIoctl",
                        caseId: "ClientAndServerHandleValidateNegotiateAndSnapshotEnumerationAndRejectUnsupportedWildcardIoctlsWithHeaders",
                        displayName: "Client and server loopback handle validate-negotiate and bounded snapshot enumeration and reject unsupported wildcard SMB2 IOCTL requests with headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropIoctl_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 4);
                                ulong sessionId = client.SessionId ?? throw new InvalidOperationException("Expected the loopback client session to be authenticated before IOCTL validation.");

                                Smb2Header validateIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: sessionId);
                                Smb2IoctlRequest validateIoctlRequest = client.CreateValidateNegotiateInfoRequest(maxOutputResponse: 256);
                                server.ValidateAndAcceptRequestHeader(validateIoctlHeader, Smb2Command.Ioctl, expectedSessionId: sessionId, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> validateIoctlResult = server.HandleIoctl(sessionId, treeId, validateIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(validateIoctlHeader, validateIoctlResult.Status, sessionId: sessionId, treeId: treeId));
                                TestAssertions.Equal(NtStatus.Success, validateIoctlResult.Status, "Expected loopback validate-negotiate IOCTL requests to succeed.");
                                ValidateNegotiateInfoResponse validateIoctlResponse = client.ApplyValidateNegotiateInfoResult(validateIoctlResult.Status, validateIoctlResult.Response);
                                TestAssertions.Equal(client.NegotiatedDialect!.Value, validateIoctlResponse.Dialect, "Expected loopback validate-negotiate responses to preserve the negotiated dialect.");
                                TestAssertions.True(client.IsSecureNegotiateValidated, "Expected successful loopback validate-negotiate coverage to mark the client session as validated.");

                                Smb2Header createHeader = client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value);
                                Smb2CreateRequest createRequest = client.CreateCreateRequest(treeId, "notes.txt", createDisposition: Smb2CreateDisposition.Open);
                                server.ValidateAndAcceptRequestHeader(createHeader, Smb2Command.Create, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId.Value, treeId, createRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(createHeader, createResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                OpenState openState = client.ApplyCreateResult(treeId, "notes.txt", createResult.Status, createResult.Response);

                                Smb2Header openIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: client.SessionId.Value);
                                Smb2IoctlRequest openIoctlRequest = client.CreateEnumerateSnapshotsRequest(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    maxOutputResponse: 512);
                                server.ValidateAndAcceptRequestHeader(openIoctlHeader, Smb2Command.Ioctl, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> openIoctlResult = server.HandleIoctl(client.SessionId.Value, treeId, openIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(openIoctlHeader, openIoctlResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                TestAssertions.Equal(NtStatus.Success, openIoctlResult.Status, "Expected bounded snapshot enumeration to succeed in loopback coverage.");
                                Smb2IoctlResponseValidator.Validate(openIoctlResult.Response);
                                SrvSnapshotArray snapshotArray = client.ApplyEnumerateSnapshotsResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    openIoctlResult.Status,
                                    openIoctlResult.Response);
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected the bounded loopback snapshot enumeration slice to expose no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected the bounded loopback snapshot enumeration slice to return an empty snapshot list.");

                                Smb2Header wildcardIoctlHeader = client.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: client.SessionId.Value);
                                Smb2IoctlRequest wildcardIoctlRequest = client.CreateConnectionIoctlRequest(
                                    (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                    maxOutputResponse: 512);
                                server.ValidateAndAcceptRequestHeader(wildcardIoctlHeader, Smb2Command.Ioctl, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2IoctlResponse> wildcardIoctlResult = server.HandleIoctl(client.SessionId.Value, treeId, wildcardIoctlRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(wildcardIoctlHeader, wildcardIoctlResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                TestAssertions.Equal(NtStatus.NotSupported, wildcardIoctlResult.Status, "Expected unsupported wildcard loopback IOCTL requests to remain non-implemented.");
                                TestAssertions.Equal(UInt64.MaxValue, wildcardIoctlResult.Response.PersistentFileId, "Expected wildcard loopback IOCTL responses to preserve the wildcard file identifier.");

                                Smb2Header closeHeader = client.CreateRequestHeader(Smb2Command.Close, treeId, sessionId: client.SessionId.Value);
                                Smb2CloseRequest closeRequest = client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId);
                                server.ValidateAndAcceptRequestHeader(closeHeader, Smb2Command.Close, expectedSessionId: client.SessionId.Value, expectedTreeId: treeId);
                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(client.SessionId.Value, treeId, closeRequest);
                                client.ApplyResponseHeader(server.CreateResponseHeader(closeHeader, closeResult.Status, sessionId: client.SessionId.Value, treeId: treeId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);

                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback IOCTL close path to clear the tracked open.");
                                TestAssertions.Equal(4, client.AvailableCredits, "Expected loopback IOCTL requests, including snapshot enumeration, to preserve the negotiated client credit window.");
                                TestAssertions.Equal(4, server.AvailableCredits, "Expected loopback IOCTL requests, including snapshot enumeration, to preserve the negotiated server credit window.");
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
