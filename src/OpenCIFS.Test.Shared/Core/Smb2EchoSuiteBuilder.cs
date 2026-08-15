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
    internal static class Smb2EchoSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Echo",
                displayName: "SMB2 echo codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Echo",
                        caseId: "EchoMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 echo messages round-trip and trim compounded zero padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            byte[] encodedEchoRequest = echoRequest.ToByteArray();
                            Smb2EchoRequest parsedEchoRequest = Smb2EchoRequest.ReadFrom(encodedEchoRequest);
                            Smb2EchoRequestValidator.Validate(parsedEchoRequest);
                            TestAssertions.SequenceEqual(encodedEchoRequest, parsedEchoRequest.ToByteArray(), "The SMB2 echo request encoding changed.");

                            byte[] paddedEchoRequest = Combine(encodedEchoRequest, new byte[4]);
                            byte[] trimmedEchoRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Echo, paddedEchoRequest);
                            TestAssertions.SequenceEqual(encodedEchoRequest, trimmedEchoRequest, "Unexpected compounded SMB2 echo request trimming result.");

                            Smb2EchoResponse echoResponse = new Smb2EchoResponse();
                            byte[] encodedEchoResponse = echoResponse.ToByteArray();
                            Smb2EchoResponse parsedEchoResponse = Smb2EchoResponse.ReadFrom(encodedEchoResponse);
                            Smb2EchoResponseValidator.Validate(parsedEchoResponse);
                            TestAssertions.SequenceEqual(encodedEchoResponse, parsedEchoResponse.ToByteArray(), "The SMB2 echo response encoding changed.");

                            byte[] paddedEchoResponse = Combine(encodedEchoResponse, new byte[4]);
                            byte[] trimmedEchoResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Echo, paddedEchoResponse);
                            TestAssertions.SequenceEqual(encodedEchoResponse, trimmedEchoResponse, "Unexpected compounded SMB2 echo response trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Echo",
                        caseId: "EchoMessagesRejectMalformedInputs",
                        displayName: "SMB2 echo codecs reject truncated or null inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2EchoRequest.ReadFrom(new byte[3]),
                                "A truncated SMB2 echo request should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2EchoResponse.ReadFrom(new byte[3]),
                                "A truncated SMB2 echo response should fail to parse.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2EchoRequestValidator.Validate(null!),
                                "A null SMB2 echo request should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2EchoResponseValidator.Validate(null!),
                                "A null SMB2 echo response should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
