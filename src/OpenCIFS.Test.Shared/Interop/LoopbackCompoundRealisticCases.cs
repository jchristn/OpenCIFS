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
    internal static class LoopbackCompoundRealisticCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackCompound",
                        caseId: "ClientAndServerCompleteRealisticRelatedCompoundReadWriteAndMetadataChains",
                        displayName: "Client and server loopback complete realistic related compounded create-write-flush-close, create-query-close, and open-read-close chains",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropRelatedCompoundRealistic_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateClient();
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTreeWithHeaders(server, client, credential, creditRequest: 12);
                                byte[] payload = Encoding.UTF8.GetBytes("realistic-compound-data");

                                Smb2CompoundPacket createWriteFlushClosePacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value),
                                            client.CreateCreateRequest(treeId, "docs\\compound.txt", createDisposition: Smb2CreateDisposition.OverwriteIf).ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.Write, sessionId: client.SessionId!.Value),
                                            new Smb2WriteRequest
                                            {
                                                Offset = 0,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Flags = Smb2WriteFlags.None,
                                                Channel = 0,
                                                RemainingBytes = 0,
                                                WriteChannelInfo = Array.Empty<byte>(),
                                                DataBuffer = payload
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.Flush, sessionId: client.SessionId!.Value),
                                            new Smb2FlushRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: client.SessionId!.Value),
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });
                                Smb2CompoundPacket createWriteFlushCloseResponsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(createWriteFlushClosePacket.ToByteArray()));
                                Smb2CompoundPacket parsedCreateWriteFlushCloseResponsePacket = Smb2CompoundPacket.ReadFrom(createWriteFlushCloseResponsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedCreateWriteFlushCloseResponsePacket);

                                OpenState createdOpenState = client.ApplyCreateResult(
                                    treeId,
                                    "docs\\compound.txt",
                                    parsedCreateWriteFlushCloseResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateWriteFlushCloseResponsePacket.Entries[0].Header.Command, parsedCreateWriteFlushCloseResponsePacket.Entries[0].Payload)));
                                uint writtenCount = client.ApplyWriteResult(
                                    createdOpenState.PersistentFileId,
                                    createdOpenState.VolatileFileId,
                                    parsedCreateWriteFlushCloseResponsePacket.Entries[1].Header.Status,
                                    Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateWriteFlushCloseResponsePacket.Entries[1].Header.Command, parsedCreateWriteFlushCloseResponsePacket.Entries[1].Payload)));
                                client.ApplyFlushResult(
                                    createdOpenState.PersistentFileId,
                                    createdOpenState.VolatileFileId,
                                    parsedCreateWriteFlushCloseResponsePacket.Entries[2].Header.Status,
                                    Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateWriteFlushCloseResponsePacket.Entries[2].Header.Command, parsedCreateWriteFlushCloseResponsePacket.Entries[2].Payload)));
                                client.ApplyCloseResult(
                                    createdOpenState.PersistentFileId,
                                    createdOpenState.VolatileFileId,
                                    parsedCreateWriteFlushCloseResponsePacket.Entries[3].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateWriteFlushCloseResponsePacket.Entries[3].Header.Command, parsedCreateWriteFlushCloseResponsePacket.Entries[3].Payload)));
                                TestAssertions.Equal((uint)payload.Length, writtenCount, "Expected the realistic related compounded write leg to acknowledge the full payload.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the realistic related compounded write chain to close the temporary open.");

                                Smb2CompoundPacket createQueryClosePacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value),
                                            client.CreateCreateRequest(treeId, "docs\\compound.txt").ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: client.SessionId!.Value),
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.AllInformation,
                                                OutputBufferLength = 1024,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: client.SessionId!.Value),
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });
                                Smb2CompoundPacket createQueryCloseResponsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(createQueryClosePacket.ToByteArray()));
                                Smb2CompoundPacket parsedCreateQueryCloseResponsePacket = Smb2CompoundPacket.ReadFrom(createQueryCloseResponsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedCreateQueryCloseResponsePacket);

                                OpenState queryOpenState = client.ApplyCreateResult(
                                    treeId,
                                    "docs\\compound.txt",
                                    parsedCreateQueryCloseResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateQueryCloseResponsePacket.Entries[0].Header.Command, parsedCreateQueryCloseResponsePacket.Entries[0].Payload)));
                                FileAllInformation allInformation = FileAllInformation.ReadFrom(client.ApplyQueryInfoResult(
                                    queryOpenState.PersistentFileId,
                                    queryOpenState.VolatileFileId,
                                    parsedCreateQueryCloseResponsePacket.Entries[1].Header.Status,
                                    Smb2QueryInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateQueryCloseResponsePacket.Entries[1].Header.Command, parsedCreateQueryCloseResponsePacket.Entries[1].Payload))));
                                client.ApplyCloseResult(
                                    queryOpenState.PersistentFileId,
                                    queryOpenState.VolatileFileId,
                                    parsedCreateQueryCloseResponsePacket.Entries[2].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedCreateQueryCloseResponsePacket.Entries[2].Header.Command, parsedCreateQueryCloseResponsePacket.Entries[2].Payload)));
                                TestAssertions.Equal((ulong)payload.Length, allInformation.StandardInformation.EndOfFile, "Expected the realistic related compounded query leg to report the current EOF.");
                                TestAssertions.Equal("docs\\compound.txt", allInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name from the realistic related compounded query leg.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the realistic related compounded query chain to close the temporary open.");

                                Smb2CompoundPacket openReadClosePacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value),
                                            client.CreateCreateRequest(treeId, "docs\\compound.txt", desiredAccess: 0x80000000U, createDisposition: Smb2CreateDisposition.Open).ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.Read, sessionId: client.SessionId!.Value),
                                            new Smb2ReadRequest
                                            {
                                                Length = (uint)payload.Length,
                                                Offset = 0,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                MinimumCount = (uint)payload.Length,
                                                Channel = 0,
                                                RemainingBytes = 0,
                                                ReadChannelInfo = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: client.SessionId!.Value),
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });
                                Smb2CompoundPacket openReadCloseResponsePacket = server.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(openReadClosePacket.ToByteArray()));
                                Smb2CompoundPacket parsedOpenReadCloseResponsePacket = Smb2CompoundPacket.ReadFrom(openReadCloseResponsePacket.ToByteArray());
                                client.ApplyCompoundResponsePacket(parsedOpenReadCloseResponsePacket);

                                OpenState readOpenState = client.ApplyCreateResult(
                                    treeId,
                                    "docs\\compound.txt",
                                    parsedOpenReadCloseResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedOpenReadCloseResponsePacket.Entries[0].Header.Command, parsedOpenReadCloseResponsePacket.Entries[0].Payload)));
                                byte[] readBytes = client.ApplyReadResult(
                                    readOpenState.PersistentFileId,
                                    readOpenState.VolatileFileId,
                                    parsedOpenReadCloseResponsePacket.Entries[1].Header.Status,
                                    Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedOpenReadCloseResponsePacket.Entries[1].Header.Command, parsedOpenReadCloseResponsePacket.Entries[1].Payload)));
                                client.ApplyCloseResult(
                                    readOpenState.PersistentFileId,
                                    readOpenState.VolatileFileId,
                                    parsedOpenReadCloseResponsePacket.Entries[2].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedOpenReadCloseResponsePacket.Entries[2].Header.Command, parsedOpenReadCloseResponsePacket.Entries[2].Payload)));
                                TestAssertions.SequenceEqual(payload, readBytes, "Expected the realistic related compounded read leg to round-trip the file payload.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the realistic related compounded read chain to close the temporary open.");
                                TestAssertions.True(parsedOpenReadCloseResponsePacket.Entries[0].Header.NextCommand != 0, "Expected the realistic related compounded response packet to preserve next-command offsets.");
                                TestAssertions.SequenceEqual(payload, File.ReadAllBytes(Path.Combine(sharePath, "docs", "compound.txt")), "Unexpected bytes persisted by the realistic related compounded loopback flows.");
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
                        caseId: "ClientAndServerCompleteEncryptedRealisticRelatedCompoundChainsUnderSmb302",
                        displayName: "Client and server loopback complete encrypted realistic related compound chains under SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropEncryptedCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "docs"));

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath, maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: true);
                                OpenCifsClientSession client = CreateNegotiatedClient(server, maximumDialect: SmbDialect.Smb302, preferEncryption: true);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateEncryptedLoopbackSessionAndTree(server, client, credential, creditRequest: 12);
                                byte[] payload = Encoding.UTF8.GetBytes("realistic-compound-data");

                                Smb2CompoundPacket createWriteFlushCloseResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(
                                        new List<Smb2CompoundPacketEntry>
                                        {
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value),
                                                client.CreateCreateRequest(treeId, "docs\\compound.txt", createDisposition: Smb2CreateDisposition.OverwriteIf).ToByteArray()),
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRelatedRequestHeader(Smb2Command.Write, sessionId: client.SessionId!.Value),
                                                new Smb2WriteRequest
                                                {
                                                    Offset = 0,
                                                    PersistentFileId = UInt64.MaxValue,
                                                    VolatileFileId = UInt64.MaxValue,
                                                    Flags = Smb2WriteFlags.None,
                                                    Channel = 0,
                                                    RemainingBytes = 0,
                                                    WriteChannelInfo = Array.Empty<byte>(),
                                                    DataBuffer = payload
                                                }.ToByteArray()),
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRelatedRequestHeader(Smb2Command.Flush, sessionId: client.SessionId!.Value),
                                                new Smb2FlushRequest
                                                {
                                                    PersistentFileId = UInt64.MaxValue,
                                                    VolatileFileId = UInt64.MaxValue
                                                }.ToByteArray()),
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: client.SessionId!.Value),
                                                new Smb2CloseRequest
                                                {
                                                    PersistentFileId = UInt64.MaxValue,
                                                    VolatileFileId = UInt64.MaxValue
                                                }.ToByteArray())
                                        }),
                                    "encrypted create-write-flush-close");

                                OpenState createdOpenState = client.ApplyCreateResult(
                                    treeId,
                                    "docs\\compound.txt",
                                    createWriteFlushCloseResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(createWriteFlushCloseResponsePacket.Entries[0].Header.Command, createWriteFlushCloseResponsePacket.Entries[0].Payload)));
                                uint writtenCount = client.ApplyWriteResult(
                                    createdOpenState.PersistentFileId,
                                    createdOpenState.VolatileFileId,
                                    createWriteFlushCloseResponsePacket.Entries[1].Header.Status,
                                    Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(createWriteFlushCloseResponsePacket.Entries[1].Header.Command, createWriteFlushCloseResponsePacket.Entries[1].Payload)));
                                client.ApplyFlushResult(
                                    createdOpenState.PersistentFileId,
                                    createdOpenState.VolatileFileId,
                                    createWriteFlushCloseResponsePacket.Entries[2].Header.Status,
                                    Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(createWriteFlushCloseResponsePacket.Entries[2].Header.Command, createWriteFlushCloseResponsePacket.Entries[2].Payload)));
                                client.ApplyCloseResult(
                                    createdOpenState.PersistentFileId,
                                    createdOpenState.VolatileFileId,
                                    createWriteFlushCloseResponsePacket.Entries[3].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(createWriteFlushCloseResponsePacket.Entries[3].Header.Command, createWriteFlushCloseResponsePacket.Entries[3].Payload)));
                                TestAssertions.Equal((uint)payload.Length, writtenCount, "Expected the encrypted realistic related compounded write leg to acknowledge the full payload.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the encrypted realistic related compounded write chain to close the temporary open.");

                                Smb2CompoundPacket openReadCloseResponsePacket = RoundTripEncryptedPacket(
                                    server,
                                    client,
                                    new Smb2CompoundPacket(
                                        new List<Smb2CompoundPacketEntry>
                                        {
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRequestHeader(Smb2Command.Create, treeId, sessionId: client.SessionId!.Value),
                                                client.CreateCreateRequest(treeId, "docs\\compound.txt", desiredAccess: 0x80000000U, createDisposition: Smb2CreateDisposition.Open).ToByteArray()),
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRelatedRequestHeader(Smb2Command.Read, sessionId: client.SessionId!.Value),
                                                new Smb2ReadRequest
                                                {
                                                    Length = (uint)payload.Length,
                                                    Offset = 0,
                                                    PersistentFileId = UInt64.MaxValue,
                                                    VolatileFileId = UInt64.MaxValue,
                                                    MinimumCount = (uint)payload.Length,
                                                    Channel = 0,
                                                    RemainingBytes = 0,
                                                    ReadChannelInfo = Array.Empty<byte>()
                                                }.ToByteArray()),
                                            new Smb2CompoundPacketEntry(
                                                client.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: client.SessionId!.Value),
                                                new Smb2CloseRequest
                                                {
                                                    PersistentFileId = UInt64.MaxValue,
                                                    VolatileFileId = UInt64.MaxValue
                                                }.ToByteArray())
                                        }),
                                    "encrypted open-read-close");

                                OpenState readOpenState = client.ApplyCreateResult(
                                    treeId,
                                    "docs\\compound.txt",
                                    openReadCloseResponsePacket.Entries[0].Header.Status,
                                    Smb2CreateResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(openReadCloseResponsePacket.Entries[0].Header.Command, openReadCloseResponsePacket.Entries[0].Payload)));
                                byte[] readBytes = client.ApplyReadResult(
                                    readOpenState.PersistentFileId,
                                    readOpenState.VolatileFileId,
                                    openReadCloseResponsePacket.Entries[1].Header.Status,
                                    Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(openReadCloseResponsePacket.Entries[1].Header.Command, openReadCloseResponsePacket.Entries[1].Payload)));
                                client.ApplyCloseResult(
                                    readOpenState.PersistentFileId,
                                    readOpenState.VolatileFileId,
                                    openReadCloseResponsePacket.Entries[2].Header.Status,
                                    Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(openReadCloseResponsePacket.Entries[2].Header.Command, openReadCloseResponsePacket.Entries[2].Payload)));
                                TestAssertions.SequenceEqual(payload, readBytes, "Expected the encrypted realistic related compounded read leg to round-trip the file payload.");
                                TestAssertions.True(openReadCloseResponsePacket.Entries[0].Header.NextCommand != 0, "Expected the encrypted realistic related compounded response packet to preserve next-command offsets.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the encrypted realistic related compounded read chain to close the temporary open.");
                                TestAssertions.SequenceEqual(payload, File.ReadAllBytes(Path.Combine(sharePath, "docs", "compound.txt")), "Unexpected bytes persisted by the encrypted realistic related compounded loopback flows.");
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
