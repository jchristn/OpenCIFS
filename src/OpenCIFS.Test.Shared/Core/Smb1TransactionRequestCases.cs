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
    internal static class Smb1TransactionRequestCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "NetBiosSessionRequestRoundTripsCalledAndCallingNamesAndRejectsMalformedShapes",
                        displayName: "Bounded NetBIOS SESSION_REQUEST round-trips called/calling names and rejects malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NetBiosEncodedName called = NetBiosEncodedName.FromServiceName("FILESERVER", NetBiosEncodedName.FileServerServiceSuffix);
                            NetBiosEncodedName calling = NetBiosEncodedName.FromServiceName("WORKSTATION", NetBiosEncodedName.WorkstationServiceSuffix);

                            NetBiosSessionRequest request = new NetBiosSessionRequest
                            {
                                CalledName = called,
                                CallingName = calling
                            };

                            byte[] wireBytes = request.ToByteArray();
                            TestAssertions.Equal(NetBiosSessionServiceHeader.Size + NetBiosSessionRequest.PayloadLength, wireBytes.Length, "Unexpected NetBIOS SESSION_REQUEST wire length.");

                            NetBiosSessionRequest parsed = NetBiosSessionRequest.ReadFrom(wireBytes);
                            TestAssertions.SequenceEqual(called.RawName, parsed.CalledName.RawName, "Unexpected NetBIOS SESSION_REQUEST called name after round-trip.");
                            TestAssertions.SequenceEqual(calling.RawName, parsed.CallingName.RawName, "Unexpected NetBIOS SESSION_REQUEST calling name after round-trip.");

                            byte[] tampered = (byte[])wireBytes.Clone();
                            tampered[NetBiosSessionServiceHeader.Size] = 0x21;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosSessionRequest.ReadFrom(tampered),
                                "NetBIOS SESSION_REQUEST should reject an encoded-name length marker other than 0x20.");

                            byte[] truncated = new byte[NetBiosSessionServiceHeader.Size + NetBiosSessionRequest.PayloadLength - 1];
                            Buffer.BlockCopy(wireBytes, 0, truncated, 0, truncated.Length);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosSessionRequest.ReadFrom(truncated),
                                "NetBIOS SESSION_REQUEST should reject buffers that are too short.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "NetBiosNegativeSessionResponseRoundTripsErrorCodeAndRejectsMalformedShapes",
                        displayName: "Bounded NetBIOS NEGATIVE_SESSION_RESPONSE round-trips error code and rejects malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NetBiosNegativeSessionResponse response = new NetBiosNegativeSessionResponse
                            {
                                ErrorCode = NetBiosNegativeSessionResponseErrorCode.CalledNameNotPresent
                            };

                            byte[] wireBytes = response.ToByteArray();
                            TestAssertions.Equal(NetBiosSessionServiceHeader.Size + NetBiosNegativeSessionResponse.PayloadLength, wireBytes.Length, "Unexpected NetBIOS NEGATIVE_SESSION_RESPONSE wire length.");

                            NetBiosNegativeSessionResponse parsed = NetBiosNegativeSessionResponse.ReadFrom(wireBytes);
                            TestAssertions.Equal(NetBiosNegativeSessionResponseErrorCode.CalledNameNotPresent, parsed.ErrorCode, "Unexpected NetBIOS NEGATIVE_SESSION_RESPONSE error code after round-trip.");

                            byte[] tamperedHeader = (byte[])wireBytes.Clone();
                            tamperedHeader[0] = (byte)NetBiosSessionMessageType.SessionMessage;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosNegativeSessionResponse.ReadFrom(tamperedHeader),
                                "NetBIOS NEGATIVE_SESSION_RESPONSE should reject PDUs with a non-NEGATIVE_SESSION_RESPONSE message type.");

                            byte[] tamperedLength = (byte[])wireBytes.Clone();
                            tamperedLength[2] = 0x00;
                            tamperedLength[3] = 0x02;
                            byte[] grown = new byte[wireBytes.Length + 1];
                            Buffer.BlockCopy(tamperedLength, 0, grown, 0, tamperedLength.Length);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosNegativeSessionResponse.ReadFrom(grown),
                                "NetBIOS NEGATIVE_SESSION_RESPONSE should reject PDUs whose declared length is not 1.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1Transaction2RequestRoundTripsSubCommandWithAlignedParameterAndDataBlocks",
                        displayName: "Bounded SMB1 TRANSACTION2 request round-trips sub-command with aligned parameter and data blocks",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x05, 0x01, 0x00, 0x00, 0x07, 0x01 };
                            byte[] data = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };

                            Smb1Transaction2Request request = new Smb1Transaction2Request
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction2,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                SubCommand = Smb1Transaction2SubCommand.QueryPathInformation,
                                TotalParameterCount = (ushort)parameters.Length,
                                TotalDataCount = (ushort)data.Length,
                                MaxParameterCount = 0x0040,
                                MaxDataCount = 0x4000,
                                MaxSetupCount = 0,
                                Flags = 0,
                                Timeout = 0,
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] requestBytes = request.ToByteArray();
                            Smb1Transaction2Request parsedRequest = Smb1Transaction2Request.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.SubCommand, parsedRequest.SubCommand, "Unexpected SMB1 TRANSACTION2 SubCommand after round-trip.");
                            TestAssertions.Equal(request.TotalParameterCount, parsedRequest.TotalParameterCount, "Unexpected SMB1 TRANSACTION2 TotalParameterCount after round-trip.");
                            TestAssertions.Equal(request.TotalDataCount, parsedRequest.TotalDataCount, "Unexpected SMB1 TRANSACTION2 TotalDataCount after round-trip.");
                            TestAssertions.SequenceEqual(parameters, parsedRequest.Parameters, "Unexpected SMB1 TRANSACTION2 Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedRequest.Data, "Unexpected SMB1 TRANSACTION2 Data after round-trip.");

                            byte[] tampered = (byte[])requestBytes.Clone();
                            int byteCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (15 * sizeof(ushort));
                            tampered[byteCountIndex] = 0xFF;
                            tampered[byteCountIndex + 1] = 0xFF;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1Transaction2Request.ReadFrom(tampered),
                                "SMB1 TRANSACTION2 request should reject ByteCount that exceeds the buffer.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1Transaction2ResponseRoundTripsParameterAndDataBlocksAndRejectsMalformedShapes",
                        displayName: "Bounded SMB1 TRANSACTION2 response round-trips parameter and data blocks and rejects malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x00, 0x00 };
                            byte[] data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };

                            Smb1Transaction2Response response = new Smb1Transaction2Response
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction2,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = (ushort)parameters.Length,
                                TotalDataCount = (ushort)data.Length,
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] responseBytes = response.ToByteArray();
                            Smb1Transaction2Response parsedResponse = Smb1Transaction2Response.ReadFrom(responseBytes);
                            TestAssertions.SequenceEqual(parameters, parsedResponse.Parameters, "Unexpected SMB1 TRANSACTION2 response Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedResponse.Data, "Unexpected SMB1 TRANSACTION2 response Data after round-trip.");

                            byte[] tampered = (byte[])responseBytes.Clone();
                            int setupCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (10 * sizeof(ushort));
                            tampered[setupCountIndex] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1Transaction2Response.ReadFrom(tampered),
                                "SMB1 TRANSACTION2 response should reject non-zero SetupCount.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TransactionRequestRoundTripsUnicodePipeNameAndSetupWordsAndRejectsMismatchedSetupCount",
                        displayName: "Bounded SMB1 TRANSACTION request round-trips Unicode pipe name and setup words and rejects mismatched SetupCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x01, 0x00, 0x02, 0x00 };
                            byte[] data = new byte[] { 0xAA, 0xBB, 0xCC };

                            Smb1TransactionRequest request = new Smb1TransactionRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = (ushort)parameters.Length,
                                TotalDataCount = (ushort)data.Length,
                                MaxParameterCount = 0x40,
                                MaxDataCount = 0x4000,
                                MaxSetupCount = 0,
                                Flags = 0,
                                Timeout = 0,
                                Setup = new ushort[] { 0x0026, 0x4242 },
                                Name = "\\PIPE\\LANMAN",
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] requestBytes = request.ToByteArray();
                            Smb1TransactionRequest parsedRequest = Smb1TransactionRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.Name, parsedRequest.Name, "Unexpected SMB1 TRANSACTION Name after round-trip.");
                            TestAssertions.Equal(2, parsedRequest.Setup.Length, "Unexpected SMB1 TRANSACTION Setup count after round-trip.");
                            TestAssertions.Equal(request.Setup[0], parsedRequest.Setup[0], "Unexpected SMB1 TRANSACTION Setup[0] after round-trip.");
                            TestAssertions.Equal(request.Setup[1], parsedRequest.Setup[1], "Unexpected SMB1 TRANSACTION Setup[1] after round-trip.");
                            TestAssertions.SequenceEqual(parameters, parsedRequest.Parameters, "Unexpected SMB1 TRANSACTION Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedRequest.Data, "Unexpected SMB1 TRANSACTION Data after round-trip.");

                            byte[] tampered = (byte[])requestBytes.Clone();
                            int setupCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (13 * sizeof(ushort));
                            tampered[setupCountIndex] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1TransactionRequest.ReadFrom(tampered),
                                "SMB1 TRANSACTION request should reject SetupCount that disagrees with the WordCount-implied setup-word count.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NtTransactRequestRoundTripsFunctionAnd32BitParameterDataLengthsAndRejectsMismatchedSetupCount",
                        displayName: "Bounded SMB1 NT_TRANSACT request round-trips Function and 32-bit parameter/data lengths and rejects mismatched SetupCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
                            byte[] data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

                            Smb1NtTransactRequest request = new Smb1NtTransactRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtTransact,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                MaxSetupCount = 0,
                                TotalParameterCount = (uint)parameters.Length,
                                TotalDataCount = (uint)data.Length,
                                MaxParameterCount = 0x0000_FFFFU,
                                MaxDataCount = 0x0010_0000U,
                                Function = 0x0004,
                                Setup = new ushort[] { 0x4242, 0x0001, 0x0040 },
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] requestBytes = request.ToByteArray();
                            Smb1NtTransactRequest parsedRequest = Smb1NtTransactRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.Function, parsedRequest.Function, "Unexpected SMB1 NT_TRANSACT Function after round-trip.");
                            TestAssertions.Equal(request.MaxParameterCount, parsedRequest.MaxParameterCount, "Unexpected SMB1 NT_TRANSACT MaxParameterCount after round-trip.");
                            TestAssertions.Equal(request.MaxDataCount, parsedRequest.MaxDataCount, "Unexpected SMB1 NT_TRANSACT MaxDataCount after round-trip.");
                            TestAssertions.Equal(3, parsedRequest.Setup.Length, "Unexpected SMB1 NT_TRANSACT Setup count after round-trip.");
                            TestAssertions.SequenceEqual(parameters, parsedRequest.Parameters, "Unexpected SMB1 NT_TRANSACT Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedRequest.Data, "Unexpected SMB1 NT_TRANSACT Data after round-trip.");

                            byte[] tampered = (byte[])requestBytes.Clone();
                            int setupCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + 1 + 2 + (4 * sizeof(uint)) + (4 * sizeof(uint));
                            tampered[setupCountIndex] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NtTransactRequest.ReadFrom(tampered),
                                "SMB1 NT_TRANSACT request should reject SetupCount that disagrees with the WordCount-implied setup-word count.");
                            return Task.CompletedTask;
                        }),
            };
        }
    }
}

