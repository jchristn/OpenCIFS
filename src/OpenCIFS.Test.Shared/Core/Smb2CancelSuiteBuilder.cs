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
    internal static class Smb2CancelSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Cancel",
                displayName: "SMB2 cancel codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Cancel",
                        caseId: "CancelMessagesRoundTripAndTrimCompoundedPayload",
                        displayName: "SMB2 cancel requests round-trip through wire encoding and compounded request trimming",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CancelRequest cancelRequest = new Smb2CancelRequest();
                            byte[] encodedCancelRequest = cancelRequest.ToByteArray();
                            Smb2CancelRequest parsedCancelRequest = Smb2CancelRequest.ReadFrom(encodedCancelRequest);
                            Smb2CancelRequestValidator.Validate(parsedCancelRequest);
                            TestAssertions.SequenceEqual(encodedCancelRequest, parsedCancelRequest.ToByteArray(), "The SMB2 cancel request encoding changed.");

                            byte[] paddedCancelRequest = Combine(encodedCancelRequest, new byte[4]);
                            byte[] trimmedCancelRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Cancel, paddedCancelRequest);
                            TestAssertions.SequenceEqual(encodedCancelRequest, trimmedCancelRequest, "Unexpected compounded SMB2 cancel request trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Cancel",
                        caseId: "CancelMessagesRejectMalformedInputs",
                        displayName: "SMB2 cancel requests reject malformed inputs and null validation targets",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CancelRequest.ReadFrom(new byte[3]),
                                "The SMB2 cancel request requires a 4-byte fixed body.");

                            byte[] malformedCancelRequestBytes = new Smb2CancelRequest().ToByteArray();
                            malformedCancelRequestBytes[0] = 0x05;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CancelRequest.ReadFrom(malformedCancelRequestBytes),
                                "Malformed SMB2 cancel requests should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CancelRequestValidator.Validate(null!),
                                "A null SMB2 cancel request should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
