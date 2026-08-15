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
    internal static class Smb1AdministrativeCommandCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1LogoffAndXRoundTripsAndRejectsNonZeroByteCount",
                        displayName: "Bounded SMB1 LOGOFF_ANDX round-trips and rejects non-zero ByteCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1LogoffAndX message = new Smb1LogoffAndX
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.LogoffAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                AndXCommand = 0xFF,
                                AndXOffset = 0
                            };

                            byte[] wireBytes = message.ToByteArray();
                            Smb1LogoffAndX parsed = Smb1LogoffAndX.ReadFrom(wireBytes);
                            TestAssertions.Equal((byte)0xFF, parsed.AndXCommand, "Unexpected SMB1 LOGOFF_ANDX AndX command.");
                            TestAssertions.Equal((ushort)0, parsed.AndXOffset, "Unexpected SMB1 LOGOFF_ANDX AndX offset.");

                            byte[] tampered = (byte[])wireBytes.Clone();
                            tampered[tampered.Length - 1] = 0x01;
                            tampered[tampered.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1LogoffAndX.ReadFrom(tampered),
                                "SMB1 LOGOFF_ANDX should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TreeDisconnectRoundTripsAndRejectsNonZeroByteCount",
                        displayName: "Bounded SMB1 TREE_DISCONNECT round-trips and rejects non-zero ByteCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1TreeDisconnect message = new Smb1TreeDisconnect
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TreeDisconnect,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                }
                            };

                            byte[] wireBytes = message.ToByteArray();
                            Smb1TreeDisconnect parsed = Smb1TreeDisconnect.ReadFrom(wireBytes);
                            TestAssertions.Equal((ushort)0xCAFE, parsed.Header.TreeId, "Unexpected SMB1 TREE_DISCONNECT TreeId after round-trip.");

                            byte[] tamperedDisconnect = (byte[])wireBytes.Clone();
                            tamperedDisconnect[tamperedDisconnect.Length - 1] = 0x05;
                            tamperedDisconnect[tamperedDisconnect.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1TreeDisconnect.ReadFrom(tamperedDisconnect),
                                "SMB1 TREE_DISCONNECT should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1CloseRequestAndResponseRoundTripFidAndRejectsMalformedShapes",
                        displayName: "Bounded SMB1 CLOSE request and response round-trip FID/LastWriteTime and reject malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1CloseRequest request = new Smb1CloseRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Close,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                LastWriteTime = 0x68001000U
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1CloseRequest parsedRequest = Smb1CloseRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 CLOSE FileId after round-trip.");
                            TestAssertions.Equal(request.LastWriteTime, parsedRequest.LastWriteTime, "Unexpected SMB1 CLOSE LastWriteTime after round-trip.");

                            byte[] tamperedRequest = (byte[])requestBytes.Clone();
                            tamperedRequest[tamperedRequest.Length - 1] = 0x01;
                            tamperedRequest[tamperedRequest.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1CloseRequest.ReadFrom(tamperedRequest),
                                "SMB1 CLOSE request should reject non-zero ByteCount payloads.");

                            Smb1CloseResponse response = new Smb1CloseResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Close,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                }
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1CloseResponse parsedResponse = Smb1CloseResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal((ushort)0x4242, parsedResponse.Header.MultiplexId, "Unexpected SMB1 CLOSE response MultiplexId.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x01;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1CloseResponse.ReadFrom(tamperedResponse),
                                "SMB1 CLOSE response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1EchoRequestAndResponseRoundTripPayloadAndRejectByteCountMismatch",
                        displayName: "Bounded SMB1 ECHO request and response round-trip payload and reject ByteCount mismatch",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] payload = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

                            Smb1EchoRequest request = new Smb1EchoRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Echo,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                EchoCount = 3,
                                Data = payload
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1EchoRequest parsedRequest = Smb1EchoRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal((ushort)3, parsedRequest.EchoCount, "Unexpected SMB1 ECHO EchoCount after round-trip.");
                            TestAssertions.SequenceEqual(payload, parsedRequest.Data, "Unexpected SMB1 ECHO request payload after round-trip.");

                            byte[] tamperedEchoRequest = (byte[])requestBytes.Clone();
                            int byteCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + sizeof(ushort);
                            tamperedEchoRequest[byteCountIndex] = 0xFF;
                            tamperedEchoRequest[byteCountIndex + 1] = 0xFF;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1EchoRequest.ReadFrom(tamperedEchoRequest),
                                "SMB1 ECHO request should reject ByteCount that exceeds the buffer.");

                            Smb1EchoResponse response = new Smb1EchoResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Echo,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                SequenceNumber = 2,
                                Data = payload
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1EchoResponse parsedResponse = Smb1EchoResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal((ushort)2, parsedResponse.SequenceNumber, "Unexpected SMB1 ECHO SequenceNumber after round-trip.");
                            TestAssertions.SequenceEqual(payload, parsedResponse.Data, "Unexpected SMB1 ECHO response payload after round-trip.");
                            return Task.CompletedTask;
                        }),
            };
        }
    }
}

