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
    internal static class LoopbackCompoundValidationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerRejectRelatedCompoundChainsWithoutRequiredContext",
                        displayName: "Client and server loopback reject related compounded packets that begin outside the supported synchronous compound surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientCredential credential = CreateCredential();
                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession unsupportedClient = CreateClient();
                            ulong unsupportedSessionId = AuthenticateLoopbackSessionWithHeaders(server, unsupportedClient, credential, creditRequest: 4);

                            Smb2Header echoHeader = unsupportedClient.CreateRequestHeader(Smb2Command.Echo, sessionId: unsupportedSessionId);
                            Smb2Header missingTreeReadHeader = unsupportedClient.CreateRelatedRequestHeader(Smb2Command.Read, sessionId: unsupportedSessionId);
                            Smb2CompoundPacket missingTreePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        echoHeader,
                                        unsupportedClient.CreateEchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        missingTreeReadHeader,
                                        new Smb2ReadRequest
                                        {
                                            Length = 1,
                                            Offset = 0,
                                            PersistentFileId = UInt64.MaxValue,
                                            VolatileFileId = UInt64.MaxValue,
                                            MinimumCount = 0,
                                            Channel = 0,
                                            RemainingBytes = 0,
                                            ReadChannelInfo = Array.Empty<byte>()
                                        }.ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(missingTreePacket.ToByteArray())),
                                "Expected loopback related compounded packets that begin with commands outside the supported synchronous compound surface to be rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerPropagateRelatedCreateFailureAcrossMetadataLockIoctlAndCloseOperations",
                        displayName: "Client and server loopback propagate related create failures across later metadata, locking, IOCTL, and close operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropRelatedCompoundFailure_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "collision.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 7);

                                Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
                                Smb2Header createHeader = client.CreateRelatedRequestHeader(Smb2Command.Create, sessionId: sessionId);
                                Smb2Header setInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.SetInfo, sessionId: sessionId);
                                Smb2Header queryInfoHeader = client.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: sessionId);
                                Smb2Header lockHeader = client.CreateRelatedRequestHeader(Smb2Command.Lock, sessionId: sessionId);
                                Smb2Header ioctlHeader = client.CreateRelatedRequestHeader(Smb2Command.Ioctl, sessionId: sessionId);
                                Smb2Header closeHeader = client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: sessionId);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            treeConnectHeader,
                                            client.CreateTreeConnectRequest("public").ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            createHeader,
                                            new Smb2CreateRequest
                                            {
                                                RequestedOplockLevel = Smb2OplockLevel.None,
                                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                                DesiredAccess = 0xC0000000U,
                                                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                                ShareAccess = 0x00000007U,
                                                CreateDisposition = Smb2CreateDisposition.Create,
                                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                                Name = "collision.txt",
                                                CreateContexts = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            setInfoHeader,
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            queryInfoHeader,
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            lockHeader,
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            ioctlHeader,
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            closeHeader,
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedResponsePacket);
                                client.ApplyTreeConnectResult("public", parsedResponsePacket.Entries[0].Header.TreeId, parsedResponsePacket.Entries[0].Header.Status, Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload)));

                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[1].Header.Status, "Expected the loopback related create to report the collision.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[2].Header.Status, "Expected the loopback related set-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[3].Header.Status, "Expected the loopback related query-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[4].Header.Status, "Expected the loopback related lock to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[5].Header.Status, "Expected the loopback related IOCTL to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, parsedResponsePacket.Entries[6].Header.Status, "Expected the loopback related close to inherit the create failure status.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the failed loopback related create not to allocate an open handle.");
                                TestAssertions.Equal("seed", File.ReadAllText(Path.Combine(sharePath, "collision.txt")), "Expected the loopback propagated create failure to leave the backing file unchanged.");
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
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerRejectMixedCompoundStyles",
                        displayName: "Client and server loopback reject compounded packets that mix unrelated and related styles",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateClient();
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest: 3);

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId),
                                        client.CreateEchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        client.CreateRelatedRequestHeader(Smb2Command.Logoff, sessionId: sessionId),
                                        client.CreateLogoffRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId),
                                        client.CreateEchoRequest().ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray())),
                                "Expected loopback compounded coverage to reject chains that mix unrelated and related styles.");
                            return Task.CompletedTask;
                        })
            };
        }
    }
}
