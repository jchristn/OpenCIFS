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
    internal static class Smb2NegotiateSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Negotiate",
                displayName: "SMB2 negotiate messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Negotiate",
                        caseId: "Smb2NegotiateMessagesRoundTrip",
                        displayName: "SMB2 negotiate request and response bodies round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Guid clientGuid = new Guid("00112233-4455-6677-8899-aabbccddeeff");
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.Dfs,
                                ClientGuid = clientGuid,
                                ClientStartTime = 0x0102030405060708UL,
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };

                            Smb2NegotiateRequestValidator.Validate(request);
                            byte[] encodedRequest = request.ToByteArray();
                            TestAssertions.Equal(40, encodedRequest.Length, "Unexpected SMB2 negotiate request length.");

                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(encodedRequest);
                            Smb2NegotiateRequestValidator.Validate(parsedRequest);
                            TestAssertions.Equal(clientGuid, parsedRequest.ClientGuid, "The SMB2 negotiate client GUID changed.");
                            TestAssertions.Equal(Smb2GlobalCapabilities.Dfs, parsedRequest.Capabilities, "The SMB2 negotiate request capabilities changed.");
                            TestAssertions.Equal(2, parsedRequest.Dialects.Length, "Unexpected SMB2 negotiate dialect count.");
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedRequest.Dialects[0], "Unexpected first SMB2 negotiate dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, parsedRequest.Dialects[1], "Unexpected second SMB2 negotiate dialect.");

                            byte[] negotiateContextData =
                            {
                                0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                            };
                            Smb2NegotiateRequest smb311ShapeRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = clientGuid,
                                Dialects = new SmbDialect[] { SmbDialect.Smb21, SmbDialect.Smb302, SmbDialect.Smb311 },
                                NegotiateContextCount = 1,
                                NegotiateContextData = negotiateContextData
                            };

                            byte[] encodedSmb311ShapeRequest = smb311ShapeRequest.ToByteArray();
                            Smb2NegotiateRequest parsedSmb311ShapeRequest = Smb2NegotiateRequest.ReadFrom(encodedSmb311ShapeRequest);
                            TestAssertions.Equal(64, encodedSmb311ShapeRequest.Length, "Unexpected SMB 3.1.1-style negotiate request length.");
                            TestAssertions.Equal((uint)112, parsedSmb311ShapeRequest.NegotiateContextOffset, "Unexpected SMB 3.1.1-style negotiate context offset.");
                            TestAssertions.Equal((ushort)1, parsedSmb311ShapeRequest.NegotiateContextCount, "Unexpected SMB 3.1.1-style negotiate context count.");
                            TestAssertions.Equal(SmbDialect.Smb311, parsedSmb311ShapeRequest.Dialects[2], "Expected the parser to preserve the SMB 3.1.1 dialect offer.");
                            TestAssertions.SequenceEqual(
                                negotiateContextData,
                                parsedSmb311ShapeRequest.NegotiateContextData,
                                "Expected the parser to preserve raw SMB 3.1.1-style negotiate context bytes.");

                            byte[] extendedRequest = new byte[encodedRequest.Length + 8];
                            Buffer.BlockCopy(encodedRequest, 0, extendedRequest, 0, encodedRequest.Length);
                            Buffer.BlockCopy(new byte[] { 0x44, 0x33, 0x22, 0x11, 0x02, 0x00, 0x00, 0x00 }, 0, extendedRequest, encodedRequest.Length, 8);
                            Smb2NegotiateRequest parsedExtendedRequest = Smb2NegotiateRequest.ReadFrom(extendedRequest);
                            byte[] trimmedExtendedRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Negotiate, extendedRequest);
                            TestAssertions.Equal(extendedRequest.Length, trimmedExtendedRequest.Length, "Expected negotiate trimming to preserve trailing dialect-context bytes.");
                            TestAssertions.Equal(2, parsedExtendedRequest.Dialects.Length, "Unexpected extended SMB2 negotiate dialect count.");
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedExtendedRequest.Dialects[0], "Unexpected first extended SMB2 negotiate dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, parsedExtendedRequest.Dialects[1], "Unexpected second extended SMB2 negotiate dialect.");

                            Guid serverGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f");
                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb2002,
                                ServerGuid = serverGuid,
                                Capabilities = Smb2GlobalCapabilities.None,
                                MaxTransactSize = 65536,
                                MaxReadSize = 131072,
                                MaxWriteSize = 196608,
                                SystemTime = 0x1122334455667788UL,
                                ServerStartTime = 0x0101010101010101UL,
                                SecurityBuffer = Array.Empty<byte>()
                            };

                            Smb2NegotiateResponseValidator.Validate(response);
                            byte[] encodedResponse = response.ToByteArray();
                            TestAssertions.Equal(64, encodedResponse.Length, "Unexpected SMB2 negotiate response length.");

                            Smb2NegotiateResponse parsedResponse = Smb2NegotiateResponse.ReadFrom(encodedResponse);
                            Smb2NegotiateResponseValidator.Validate(parsedResponse);
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedResponse.Dialect, "The SMB2 negotiate response dialect changed.");
                            TestAssertions.Equal(serverGuid, parsedResponse.ServerGuid, "The SMB2 negotiate server GUID changed.");
                            TestAssertions.Equal((uint)65536, parsedResponse.MaxTransactSize, "The SMB2 negotiate max transact size changed.");
                            TestAssertions.Equal((uint)131072, parsedResponse.MaxReadSize, "The SMB2 negotiate max read size changed.");
                            TestAssertions.Equal((uint)196608, parsedResponse.MaxWriteSize, "The SMB2 negotiate max write size changed.");
                            TestAssertions.Equal(0, parsedResponse.SecurityBuffer.Length, "The SMB2 negotiate security buffer should be empty in this vector.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Negotiate",
                        caseId: "Smb1MultiProtocolNegotiateRoundTrips",
                        displayName: "SMB1 multi-protocol negotiate requests round-trip and expose SMB2 bootstrap dialects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1NegotiateRequest request = new Smb1NegotiateRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Negotiate,
                                    Flags = Smb1HeaderFlags.CanonicalizedPaths | Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.LongNames | Smb1HeaderFlags2.Unicode,
                                    ProcessIdHigh = 0x1122,
                                    ProcessIdLow = 0x3344,
                                    MultiplexId = 7
                                },
                                Dialects = new string[]
                                {
                                    "NT LM 0.12",
                                    Smb1NegotiateRequest.Smb2002DialectString,
                                    Smb1NegotiateRequest.Smb2WildcardDialectString
                                }
                            };

                            byte[] encodedRequest = request.ToByteArray();
                            Smb1NegotiateRequest parsedRequest = Smb1NegotiateRequest.ReadFrom(encodedRequest);

                            TestAssertions.Equal(Smb1Command.Negotiate, parsedRequest.Header.Command, "Unexpected SMB1 negotiate command.");
                            TestAssertions.Equal(3, parsedRequest.Dialects.Length, "Unexpected SMB1 negotiate dialect count.");
                            TestAssertions.Equal("NT LM 0.12", parsedRequest.Dialects[0], "Unexpected first SMB1 negotiate dialect.");
                            TestAssertions.True(parsedRequest.ContainsDialect(Smb1NegotiateRequest.Smb2002DialectString), "Expected SMB 2.002 to be present in the multi-protocol dialect list.");
                            TestAssertions.True(parsedRequest.ContainsDialect(Smb1NegotiateRequest.Smb2WildcardDialectString), "Expected SMB 2.??? to be present in the multi-protocol dialect list.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Negotiate",
                        caseId: "Smb2NegotiateMessagesRejectMalformedInputs",
                        displayName: "SMB2 negotiate message codecs and validators reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                ClientGuid = new Guid("00112233-4455-6677-8899-aabbccddeeff"),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };
                            byte[] invalidRequestBytes = request.ToByteArray();
                            invalidRequestBytes[0] = 0x00;
                            invalidRequestBytes[1] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(invalidRequestBytes),
                                "An SMB2 negotiate request with the wrong structure size should fail to parse.");

                            Smb1NegotiateRequest smb1Request = new Smb1NegotiateRequest
                            {
                                Dialects = new string[]
                                {
                                    "NT LM 0.12",
                                    Smb1NegotiateRequest.Smb2002DialectString
                                }
                            };
                            int smb1HeaderLength = new Smb1Header().ToByteArray().Length;
                            byte[] invalidSmb1WordCountBytes = smb1Request.ToByteArray();
                            invalidSmb1WordCountBytes[smb1HeaderLength] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NegotiateRequest.ReadFrom(invalidSmb1WordCountBytes),
                                "An SMB1 multi-protocol negotiate request with a non-zero WordCount should fail to parse.");

                            byte[] invalidSmb1DialectFormatBytes = smb1Request.ToByteArray();
                            invalidSmb1DialectFormatBytes[smb1HeaderLength + 3] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NegotiateRequest.ReadFrom(invalidSmb1DialectFormatBytes),
                                "An SMB1 multi-protocol negotiate request with an invalid dialect buffer format should fail to parse.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => new Smb1NegotiateRequest
                                {
                                    Header = new Smb1Header
                                    {
                                        Command = Smb1Command.Echo
                                    },
                                    Dialects = new string[]
                                    {
                                        Smb1NegotiateRequest.Smb2002DialectString
                                    }
                                }.ToByteArray(),
                                "Only SMB_COM_NEGOTIATE headers should serialize through the SMB1 multi-protocol negotiate codec.");

                            byte[] unknownDialectBytes = request.ToByteArray();
                            unknownDialectBytes[38] = 0xFF;
                            unknownDialectBytes[39] = 0xFF;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(unknownDialectBytes),
                                "An SMB2 negotiate request with an unknown dialect should fail to parse.");

                            Smb2NegotiateRequest smb311ShapeRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new SmbDialect[] { SmbDialect.Smb302, SmbDialect.Smb311 },
                                NegotiateContextCount = 1,
                                NegotiateContextData = new byte[]
                                {
                                    0x01, 0x00, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD
                                }
                            };
                            byte[] malformedContextOffsetBytes = smb311ShapeRequest.ToByteArray();
                            Buffer.BlockCopy(new byte[] { 0x50, 0x00, 0x00, 0x00 }, 0, malformedContextOffsetBytes, 28, 4);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(malformedContextOffsetBytes),
                                "An SMB 3.1.1-style negotiate request with a body-relative or too-small negotiate context offset should fail to parse.");

                            Smb2NegotiateRequest duplicateDialectRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb2002 }
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2NegotiateRequestValidator.Validate(duplicateDialectRequest),
                                "Duplicate SMB2 negotiate dialects should fail validation.");

                            Smb2NegotiateResponse invalidSecurityModeResponse = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb2002,
                                ServerGuid = Guid.NewGuid(),
                                MaxTransactSize = 1,
                                MaxReadSize = 1,
                                MaxWriteSize = 1
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2NegotiateResponseValidator.Validate(invalidSecurityModeResponse),
                                "SigningRequired without SigningEnabled should fail validation.");

                            Smb2NegotiateResponse responseWithSecurityBuffer = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb2002,
                                ServerGuid = Guid.NewGuid(),
                                MaxTransactSize = 1,
                                MaxReadSize = 1,
                                MaxWriteSize = 1,
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            byte[] invalidResponseBytes = responseWithSecurityBuffer.ToByteArray();
                            invalidResponseBytes[56] = 0x7F;
                            invalidResponseBytes[57] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateResponse.ReadFrom(invalidResponseBytes),
                                "An SMB2 negotiate response with an invalid security-buffer offset should fail to parse.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
