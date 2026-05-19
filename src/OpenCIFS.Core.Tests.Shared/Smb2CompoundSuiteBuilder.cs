namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class Smb2CompoundSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Compound",
                displayName: "SMB2 compound packet framing",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Compound",
                        caseId: "CompoundPacketsRoundTripAndTrimImplementedPayloads",
                        displayName: "SMB2 compound packets round-trip with aligned offsets and trim implemented request or response payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Write, 0),
                                        new Smb2WriteRequest
                                        {
                                            Offset = 0,
                                            PersistentFileId = 11,
                                            VolatileFileId = 12,
                                            Channel = 0,
                                            RemainingBytes = 0,
                                            Flags = Smb2WriteFlags.None,
                                            DataBuffer = Encoding.ASCII.GetBytes("abc"),
                                            WriteChannelInfo = Array.Empty<byte>()
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Flush, 1),
                                        new Smb2FlushRequest
                                        {
                                            PersistentFileId = 11,
                                            VolatileFileId = 12
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 2),
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = 11,
                                            VolatileFileId = 12
                                        }.ToByteArray())
                                });
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray());

                            TestAssertions.Equal(3, parsedRequestPacket.Entries.Count, "Unexpected SMB2 compound request entry count.");
                            TestAssertions.True(parsedRequestPacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded request to point at a subsequent entry.");
                            TestAssertions.True((parsedRequestPacket.Entries[0].Header.NextCommand % 8) == 0, "Expected the first compounded request offset to remain 8-byte aligned.");
                            TestAssertions.True((parsedRequestPacket.Entries[1].Header.NextCommand % 8) == 0, "Expected the second compounded request offset to remain 8-byte aligned.");
                            TestAssertions.Equal(0U, parsedRequestPacket.Entries[2].Header.NextCommand, "Expected the final compounded request to terminate the chain.");

                            Smb2WriteRequest parsedWriteRequest = Smb2WriteRequest.ReadFrom(Smb2CompoundPayloadHelper.TrimRequestPayload(parsedRequestPacket.Entries[0].Header.Command, parsedRequestPacket.Entries[0].Payload));
                            Smb2FlushRequest parsedFlushRequest = Smb2FlushRequest.ReadFrom(Smb2CompoundPayloadHelper.TrimRequestPayload(parsedRequestPacket.Entries[1].Header.Command, parsedRequestPacket.Entries[1].Payload));
                            Smb2CloseRequest parsedCloseRequest = Smb2CloseRequest.ReadFrom(Smb2CompoundPayloadHelper.TrimRequestPayload(parsedRequestPacket.Entries[2].Header.Command, parsedRequestPacket.Entries[2].Payload));

                            TestAssertions.SequenceEqual(Encoding.ASCII.GetBytes("abc"), parsedWriteRequest.DataBuffer, "Unexpected compounded write payload.");
                            TestAssertions.Equal(12UL, parsedFlushRequest.VolatileFileId, "Unexpected compounded flush volatile file identifier.");
                            TestAssertions.Equal(11UL, parsedCloseRequest.PersistentFileId, "Unexpected compounded close persistent file identifier.");

                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Read, 0, flags: Smb2HeaderFlags.ServerToRedir),
                                        new Smb2ReadResponse
                                        {
                                            DataBuffer = Encoding.ASCII.GetBytes("payload"),
                                            DataRemaining = 0,
                                            Flags = 0
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1, flags: Smb2HeaderFlags.ServerToRedir),
                                        new Smb2CloseResponse
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            EndOfFile = 7,
                                            FileAttributes = ProtocolFileAttributes.Normal
                                        }.ToByteArray())
                                });
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                            Smb2ReadResponse parsedReadResponse = Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload));
                            Smb2CloseResponse parsedCloseResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[1].Header.Command, parsedResponsePacket.Entries[1].Payload));

                            TestAssertions.SequenceEqual(Encoding.ASCII.GetBytes("payload"), parsedReadResponse.DataBuffer, "Unexpected compounded read-response payload.");
                            TestAssertions.Equal(7UL, parsedCloseResponse.EndOfFile, "Unexpected compounded close-response EOF size.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Compound",
                        caseId: "CompoundPacketsRejectMalformedOffsetsAndPadding",
                        displayName: "SMB2 compound packets reject malformed next-command offsets and non-zero trailing padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CompoundPacket validPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Flush, 0),
                                        new Smb2FlushRequest
                                        {
                                            PersistentFileId = 1,
                                            VolatileFileId = 2
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1),
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = 1,
                                            VolatileFileId = 2
                                        }.ToByteArray())
                                });
                            byte[] malformedPacketBytes = validPacket.ToByteArray();
                            malformedPacketBytes[20] = 0x04;
                            malformedPacketBytes[21] = 0x00;
                            malformedPacketBytes[22] = 0x00;
                            malformedPacketBytes[23] = 0x00;

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CompoundPacket.ReadFrom(malformedPacketBytes),
                                "A compounded packet with a misaligned NextCommand value should fail to parse.");

                            byte[] readResponseBytes = new Smb2ReadResponse
                            {
                                DataBuffer = new byte[] { 0x01, 0x02, 0x03 },
                                DataRemaining = 0,
                                Flags = 0
                            }.ToByteArray();
                            byte[] invalidPaddedReadResponse = new byte[readResponseBytes.Length + 4];
                            Array.Copy(readResponseBytes, invalidPaddedReadResponse, readResponseBytes.Length);
                            invalidPaddedReadResponse[readResponseBytes.Length] = 0x7F;

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Read, invalidPaddedReadResponse),
                                "A compounded response payload with non-zero trailing padding should fail trimming.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Compound",
                        caseId: "CompoundPacketsPreserveRelatedOperationFlags",
                        displayName: "SMB2 compound packets preserve related-operation flags across aligned request and response headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Create, 0),
                                        new Smb2CreateRequest
                                        {
                                            RequestedOplockLevel = Smb2OplockLevel.None,
                                            ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                            DesiredAccess = 0x0012019FU,
                                            FileAttributes = ProtocolFileAttributes.Normal,
                                            ShareAccess = 0x00000007U,
                                            CreateDisposition = Smb2CreateDisposition.OpenIf,
                                            CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                            Name = "compound.txt",
                                            CreateContexts = Array.Empty<byte>()
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1, flags: Smb2HeaderFlags.RelatedOperations),
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = UInt64.MaxValue,
                                            VolatileFileId = UInt64.MaxValue
                                        }.ToByteArray())
                                });

                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray());
                            TestAssertions.Equal(Smb2HeaderFlags.RelatedOperations, parsedRequestPacket.Entries[1].Header.Flags, "Expected the related-operation request flag to round-trip.");

                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Create, 0, flags: Smb2HeaderFlags.ServerToRedir),
                                        new Smb2CreateResponse
                                        {
                                            OplockLevel = Smb2OplockLevel.None,
                                            Flags = 0,
                                            CreateAction = Smb2CreateAction.Opened,
                                            FileAttributes = ProtocolFileAttributes.Normal,
                                            PersistentFileId = 10,
                                            VolatileFileId = 11,
                                            CreateContexts = Array.Empty<byte>()
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1, flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations),
                                        new Smb2CloseResponse
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            FileAttributes = ProtocolFileAttributes.Normal
                                        }.ToByteArray())
                                });

                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                            TestAssertions.Equal(
                                Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations,
                                parsedResponsePacket.Entries[1].Header.Flags,
                                "Expected the related-operation response flag to round-trip.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
