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
    internal static class Smb1FileIoCommandCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NtCreateAndXRequestAndResponseRoundTripUnicodeFileNameAndExtendedFields",
                        displayName: "Bounded SMB1 NT_CREATE_ANDX request and response round-trip Unicode file name and extended fields",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1NtCreateAndXRequest request = new Smb1NtCreateAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtCreateAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Flags = 0x16,
                                RootDirectoryFileId = 0,
                                DesiredAccess = 0x00120089U,
                                AllocationSize = 0,
                                ExtFileAttributes = 0x00000020U,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = 0x00000001U,
                                CreateOptions = 0x00000040U,
                                ImpersonationLevel = 0x00000002U,
                                SecurityFlags = 0x03,
                                FileName = "docs\\readme.txt"
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1NtCreateAndXRequest parsedRequest = Smb1NtCreateAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.DesiredAccess, parsedRequest.DesiredAccess, "Unexpected SMB1 NT_CREATE_ANDX DesiredAccess after round-trip.");
                            TestAssertions.Equal(request.CreateDisposition, parsedRequest.CreateDisposition, "Unexpected SMB1 NT_CREATE_ANDX CreateDisposition after round-trip.");
                            TestAssertions.Equal(request.CreateOptions, parsedRequest.CreateOptions, "Unexpected SMB1 NT_CREATE_ANDX CreateOptions after round-trip.");
                            TestAssertions.Equal(request.SecurityFlags, parsedRequest.SecurityFlags, "Unexpected SMB1 NT_CREATE_ANDX SecurityFlags after round-trip.");
                            TestAssertions.Equal(request.FileName, parsedRequest.FileName, "Unexpected SMB1 NT_CREATE_ANDX FileName after round-trip.");

                            Smb1NtCreateAndXResponse response = new Smb1NtCreateAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtCreateAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                OplockLevel = 2,
                                FileId = 0x4242,
                                CreateDisposition = 1,
                                CreateTime = 0x01D89AB000000000L,
                                LastAccessTime = 0x01D89AB000000001L,
                                LastWriteTime = 0x01D89AB000000002L,
                                LastChangeTime = 0x01D89AB000000003L,
                                ExtFileAttributes = 0x00000020U,
                                AllocationSize = 4096L,
                                EndOfFile = 1234L,
                                ResourceType = 1,
                                NMPipeStatus = 0,
                                Directory = 0
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1NtCreateAndXResponse parsedResponse = Smb1NtCreateAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.FileId, parsedResponse.FileId, "Unexpected SMB1 NT_CREATE_ANDX response FileId.");
                            TestAssertions.Equal(response.OplockLevel, parsedResponse.OplockLevel, "Unexpected SMB1 NT_CREATE_ANDX response OplockLevel.");
                            TestAssertions.Equal(response.EndOfFile, parsedResponse.EndOfFile, "Unexpected SMB1 NT_CREATE_ANDX response EndOfFile.");
                            TestAssertions.Equal(response.AllocationSize, parsedResponse.AllocationSize, "Unexpected SMB1 NT_CREATE_ANDX response AllocationSize.");
                            TestAssertions.Equal(response.LastWriteTime, parsedResponse.LastWriteTime, "Unexpected SMB1 NT_CREATE_ANDX response LastWriteTime.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x01;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NtCreateAndXResponse.ReadFrom(tamperedResponse),
                                "SMB1 NT_CREATE_ANDX response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1ReadAndXRequestAndResponseRoundTrip64BitOffsetAndDataPayload",
                        displayName: "Bounded SMB1 READ_ANDX request and response round-trip 64-bit offset and data payload",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1ReadAndXRequest request = new Smb1ReadAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.ReadAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                FileOffset = 0x0000_0001_0000_0010UL,
                                MaxCountOfBytesToReturn = 4096,
                                MinCountOfBytesToReturn = 1,
                                TimeoutOrMaxCountHigh = 0xFFFFFFFFU,
                                Remaining = 0
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1ReadAndXRequest parsedRequest = Smb1ReadAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 READ_ANDX FileId after round-trip.");
                            TestAssertions.Equal(request.FileOffset, parsedRequest.FileOffset, "Unexpected SMB1 READ_ANDX 64-bit offset after round-trip.");
                            TestAssertions.Equal(request.MaxCountOfBytesToReturn, parsedRequest.MaxCountOfBytesToReturn, "Unexpected SMB1 READ_ANDX MaxCount after round-trip.");

                            byte[] tamperedRequest = (byte[])requestBytes.Clone();
                            tamperedRequest[tamperedRequest.Length - 1] = 0x05;
                            tamperedRequest[tamperedRequest.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1ReadAndXRequest.ReadFrom(tamperedRequest),
                                "SMB1 READ_ANDX request should reject non-zero ByteCount payloads.");

                            byte[] payload = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };

                            Smb1ReadAndXResponse response = new Smb1ReadAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.ReadAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Available = 0xFFFF,
                                Data = payload
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1ReadAndXResponse parsedResponse = Smb1ReadAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.Available, parsedResponse.Available, "Unexpected SMB1 READ_ANDX response Available.");
                            TestAssertions.SequenceEqual(payload, parsedResponse.Data, "Unexpected SMB1 READ_ANDX response payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1WriteAndXRequestAndResponseRoundTripDataPayloadAndRejectMalformedShapes",
                        displayName: "Bounded SMB1 WRITE_ANDX request and response round-trip data payload and reject malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

                            Smb1WriteAndXRequest request = new Smb1WriteAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.WriteAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                FileOffset = 0x0000_0002_0000_0030UL,
                                WriteMode = 0x0008,
                                Remaining = 0,
                                Data = payload
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1WriteAndXRequest parsedRequest = Smb1WriteAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 WRITE_ANDX FileId after round-trip.");
                            TestAssertions.Equal(request.FileOffset, parsedRequest.FileOffset, "Unexpected SMB1 WRITE_ANDX 64-bit offset after round-trip.");
                            TestAssertions.Equal(request.WriteMode, parsedRequest.WriteMode, "Unexpected SMB1 WRITE_ANDX WriteMode after round-trip.");
                            TestAssertions.SequenceEqual(payload, parsedRequest.Data, "Unexpected SMB1 WRITE_ANDX request payload after round-trip.");

                            Smb1WriteAndXResponse response = new Smb1WriteAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.WriteAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Count = (ushort)payload.Length,
                                Available = 0xFFFF,
                                CountHigh = 0
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1WriteAndXResponse parsedResponse = Smb1WriteAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.Count, parsedResponse.Count, "Unexpected SMB1 WRITE_ANDX response Count.");
                            TestAssertions.Equal(response.Available, parsedResponse.Available, "Unexpected SMB1 WRITE_ANDX response Available.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x05;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1WriteAndXResponse.ReadFrom(tamperedResponse),
                                "SMB1 WRITE_ANDX response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1LockingAndXRequestAndResponseRoundTripLargeFileLockRangesAndRejectMalformedShapes",
                        displayName: "Bounded SMB1 LOCKING_ANDX request and response round-trip large-file lock ranges and reject malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1LockingAndXRequest request = new Smb1LockingAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.LockingAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                LockType = Smb1LockingAndXRequest.LockTypeLargeFiles,
                                OplockLevel = 0,
                                Timeout = 5000
                            };
                            request.Locks.Add(new Smb1LockingAndXRequest.LockRange
                            {
                                ProcessId = 0x0042,
                                Offset = 0x0000_0001_0000_0010UL,
                                Length = 0x0000_0000_0000_1000UL
                            });
                            request.Unlocks.Add(new Smb1LockingAndXRequest.LockRange
                            {
                                ProcessId = 0x0042,
                                Offset = 0x0000_0002_0000_0000UL,
                                Length = 0x0000_0000_0000_2000UL
                            });

                            byte[] requestBytes = request.ToByteArray();
                            Smb1LockingAndXRequest parsedRequest = Smb1LockingAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 LOCKING_ANDX FileId after round-trip.");
                            TestAssertions.Equal(request.LockType, parsedRequest.LockType, "Unexpected SMB1 LOCKING_ANDX LockType after round-trip.");
                            TestAssertions.Equal(request.Timeout, parsedRequest.Timeout, "Unexpected SMB1 LOCKING_ANDX Timeout after round-trip.");
                            TestAssertions.Equal(1, parsedRequest.Locks.Count, "Unexpected SMB1 LOCKING_ANDX Locks count.");
                            TestAssertions.Equal(1, parsedRequest.Unlocks.Count, "Unexpected SMB1 LOCKING_ANDX Unlocks count.");
                            TestAssertions.Equal(request.Locks[0].Offset, parsedRequest.Locks[0].Offset, "Unexpected SMB1 LOCKING_ANDX lock offset after round-trip.");
                            TestAssertions.Equal(request.Locks[0].Length, parsedRequest.Locks[0].Length, "Unexpected SMB1 LOCKING_ANDX lock length after round-trip.");
                            TestAssertions.Equal(request.Unlocks[0].Offset, parsedRequest.Unlocks[0].Offset, "Unexpected SMB1 LOCKING_ANDX unlock offset after round-trip.");

                            byte[] tamperedRequest = (byte[])requestBytes.Clone();
                            tamperedRequest[ProtocolConstants.Smb1HeaderLength + 1 + (Smb1LockingAndXRequest.LockTypeOplockRelease * 0)] = 0x05;
                            int byteCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (8 * sizeof(ushort));
                            tamperedRequest[byteCountIndex] = 0x10;
                            tamperedRequest[byteCountIndex + 1] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1LockingAndXRequest.ReadFrom(tamperedRequest),
                                "SMB1 LOCKING_ANDX request should reject ByteCount mismatched with declared lock counts.");

                            Smb1LockingAndXResponse response = new Smb1LockingAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.LockingAndX,
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
                            Smb1LockingAndXResponse parsedResponse = Smb1LockingAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal((ushort)0x4242, parsedResponse.Header.MultiplexId, "Unexpected SMB1 LOCKING_ANDX response MultiplexId.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x01;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1LockingAndXResponse.ReadFrom(tamperedResponse),
                                "SMB1 LOCKING_ANDX response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
            };
        }
    }
}

