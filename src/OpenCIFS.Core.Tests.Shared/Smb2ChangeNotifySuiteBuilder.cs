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
    internal static class Smb2ChangeNotifySuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2ChangeNotify",
                displayName: "SMB2 CHANGE_NOTIFY codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2ChangeNotify",
                        caseId: "ChangeNotifyMessagesAndAsyncHeadersRoundTrip",
                        displayName: "SMB2 async headers and CHANGE_NOTIFY messages round-trip and trim compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header asyncHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Pending,
                                Command = Smb2Command.ChangeNotify,
                                CreditRequest = 3,
                                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                NextCommand = 0,
                                MessageId = 9,
                                AsyncId = 77,
                                SessionId = 88,
                                Signature = new byte[16]
                            };
                            byte[] encodedAsyncHeader = asyncHeader.ToByteArray();
                            Smb2Header parsedAsyncHeader = Smb2Header.ReadFrom(encodedAsyncHeader);
                            Smb2HeaderValidator.Validate(parsedAsyncHeader);
                            TestAssertions.Equal(77UL, parsedAsyncHeader.AsyncId, "Unexpected SMB2 async identifier.");
                            TestAssertions.Equal(0U, parsedAsyncHeader.ProcessId, "Unexpected SMB2 async ProcessId value.");
                            TestAssertions.Equal(0U, parsedAsyncHeader.TreeId, "Unexpected SMB2 async TreeId value.");

                            Smb2CompoundPacket asyncResponsePacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(asyncHeader, new Smb2ErrorResponse().ToByteArray())
                            });
                            Smb2CompoundPacket parsedAsyncResponsePacket = Smb2CompoundPacket.ReadFrom(asyncResponsePacket.ToByteArray());
                            TestAssertions.Equal(77UL, parsedAsyncResponsePacket.Entries[0].Header.AsyncId, "Expected the compounded async response to preserve AsyncId.");

                            Smb2ChangeNotifyRequest request = new Smb2ChangeNotifyRequest
                            {
                                Flags = Smb2ChangeNotifyFlags.WatchTree,
                                OutputBufferLength = 4096,
                                PersistentFileId = 10,
                                VolatileFileId = 11,
                                CompletionFilter = FileNotifyChangeFilter.FileName | FileNotifyChangeFilter.LastWrite
                            };
                            byte[] encodedRequest = request.ToByteArray();
                            Smb2ChangeNotifyRequest parsedRequest = Smb2ChangeNotifyRequest.ReadFrom(encodedRequest);
                            Smb2ChangeNotifyRequestValidator.Validate(parsedRequest);
                            byte[] trimmedRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.ChangeNotify, Combine(encodedRequest, new byte[4]));
                            TestAssertions.SequenceEqual(encodedRequest, trimmedRequest, "Unexpected compounded SMB2 CHANGE_NOTIFY request trimming result.");

                            FileNotifyInformation[] expectedEntries = new FileNotifyInformation[]
                            {
                                new FileNotifyInformation
                                {
                                    Action = FileNotifyAction.Added,
                                    FileName = "child.txt"
                                },
                                new FileNotifyInformation
                                {
                                    Action = FileNotifyAction.Modified,
                                    FileName = "subdir\\leaf.txt"
                                }
                            };
                            byte[] encodedEntries = FileNotifyInformation.EncodeEntries(expectedEntries);
                            FileNotifyInformation[] decodedEntries = FileNotifyInformation.DecodeEntries(encodedEntries);
                            TestAssertions.Equal(2, decodedEntries.Length, "Expected the FILE_NOTIFY_INFORMATION buffer to preserve both entries.");
                            TestAssertions.Equal(FileNotifyAction.Added, decodedEntries[0].Action, "Unexpected first notify action.");
                            TestAssertions.Equal("subdir\\leaf.txt", decodedEntries[1].FileName, "Unexpected second notify path.");

                            Smb2ChangeNotifyResponse response = new Smb2ChangeNotifyResponse
                            {
                                OutputBuffer = encodedEntries
                            };
                            byte[] encodedResponse = response.ToByteArray();
                            Smb2ChangeNotifyResponse parsedResponse = Smb2ChangeNotifyResponse.ReadFrom(encodedResponse);
                            Smb2ChangeNotifyResponseValidator.Validate(parsedResponse);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.ChangeNotify, Combine(encodedResponse, new byte[4]));
                            TestAssertions.SequenceEqual(encodedResponse, trimmedResponse, "Unexpected compounded SMB2 CHANGE_NOTIFY response trimming result.");

                            Smb2ErrorResponse errorResponse = new Smb2ErrorResponse();
                            byte[] encodedErrorResponse = errorResponse.ToByteArray();
                            Smb2ErrorResponse parsedErrorResponse = Smb2ErrorResponse.ReadFrom(encodedErrorResponse);
                            Smb2ErrorResponseValidator.Validate(parsedErrorResponse);
                            TestAssertions.Equal(0, parsedErrorResponse.ErrorData.Length, "Expected the bounded SMB2 error response to remain empty.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2ChangeNotify",
                        caseId: "ChangeNotifyMessagesRejectMalformedInputs",
                        displayName: "SMB2 async headers and CHANGE_NOTIFY codecs reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header invalidAsyncHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Pending,
                                Command = Smb2Command.ChangeNotify,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                MessageId = 5,
                                SessionId = 6,
                                Signature = new byte[16]
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2HeaderValidator.Validate(invalidAsyncHeader),
                                "Async SMB2 headers without an AsyncId should fail validation.");

                            byte[] malformedRequest = new Smb2ChangeNotifyRequest().ToByteArray();
                            malformedRequest[0] = 0x1F;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2ChangeNotifyRequest.ReadFrom(malformedRequest),
                                "Malformed SMB2 CHANGE_NOTIFY requests should be rejected.");

                            byte[] malformedResponse = new Smb2ChangeNotifyResponse
                            {
                                OutputBuffer = new byte[] { 0x01, 0x02 }
                            }.ToByteArray();
                            malformedResponse[2] = 0x01;
                            malformedResponse[3] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2ChangeNotifyResponse.ReadFrom(malformedResponse),
                                "Malformed SMB2 CHANGE_NOTIFY responses should be rejected.");

                            byte[] malformedNotifyEntries = FileNotifyInformation.EncodeEntries(new FileNotifyInformation[]
                            {
                                new FileNotifyInformation
                                {
                                    Action = FileNotifyAction.Added,
                                    FileName = "child.txt"
                                }
                            });
                            malformedNotifyEntries[8] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileNotifyInformation.DecodeEntries(malformedNotifyEntries),
                                "Malformed FILE_NOTIFY_INFORMATION buffers should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ChangeNotifyRequestValidator.Validate(null!),
                                "A null SMB2 CHANGE_NOTIFY request should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ChangeNotifyResponseValidator.Validate(null!),
                                "A null SMB2 CHANGE_NOTIFY response should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ErrorResponseValidator.Validate(null!),
                                "A null SMB2 error response should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
