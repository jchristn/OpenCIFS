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
    internal static class HeaderFoundationSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Headers",
                displayName: "SMB header codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "Smb1HeaderRoundTrip",
                        displayName: "SMB1 headers round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1Header header = CreateValidSmb1Header();
                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(32, encoded.Length, "Unexpected SMB1 header size.");

                            Smb1Header parsed = Smb1Header.ReadFrom(encoded);
                            Smb1HeaderValidator.Validate(parsed);
                            TestAssertions.Equal(Smb1Command.WriteAndX, parsed.Command, "Unexpected SMB1 command.");
                            TestAssertions.Equal(NtStatus.AccessDenied, parsed.Status, "Unexpected SMB1 status.");
                            TestAssertions.Equal(Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply, parsed.Flags, "Unexpected SMB1 flags.");
                            TestAssertions.Equal(Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity, parsed.Flags2, "Unexpected SMB1 flags2.");
                            TestAssertions.Equal((ushort)0x1234, parsed.ProcessIdHigh, "Unexpected SMB1 PID high.");
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 }, parsed.Signature, "Unexpected SMB1 signature.");
                            TestAssertions.Equal((ushort)0x4567, parsed.TreeId, "Unexpected SMB1 tree identifier.");
                            TestAssertions.Equal((ushort)0x89AB, parsed.ProcessIdLow, "Unexpected SMB1 PID low.");
                            TestAssertions.Equal((ushort)0xCDEF, parsed.UserId, "Unexpected SMB1 user identifier.");
                            TestAssertions.Equal((ushort)0x2468, parsed.MultiplexId, "Unexpected SMB1 multiplex identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "Smb2HeaderRoundTrip",
                        displayName: "SMB2 headers round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header header = CreateValidSmb2Header();
                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(64, encoded.Length, "Unexpected SMB2 header size.");

                            Smb2Header parsed = Smb2Header.ReadFrom(encoded);
                            Smb2HeaderValidator.Validate(parsed);
                            TestAssertions.Equal((ushort)2, parsed.CreditCharge, "Unexpected SMB2 credit charge.");
                            TestAssertions.Equal(NtStatus.BufferTooSmall, parsed.Status, "Unexpected SMB2 status.");
                            TestAssertions.Equal(Smb2Command.QueryInfo, parsed.Command, "Unexpected SMB2 command.");
                            TestAssertions.Equal((ushort)7, parsed.CreditRequest, "Unexpected SMB2 credit request.");
                            TestAssertions.Equal(Smb2HeaderFlags.Signed | Smb2HeaderFlags.ServerToRedir, parsed.Flags, "Unexpected SMB2 flags.");
                            TestAssertions.Equal(16U, parsed.NextCommand, "Unexpected SMB2 next-command offset.");
                            TestAssertions.Equal(0x0102030405060708UL, parsed.MessageId, "Unexpected SMB2 message identifier.");
                            TestAssertions.Equal(0x0A0B0C0DU, parsed.ProcessId, "Unexpected SMB2 process identifier.");
                            TestAssertions.Equal(0x10203040U, parsed.TreeId, "Unexpected SMB2 tree identifier.");
                            TestAssertions.Equal(0x1122334455667788UL, parsed.SessionId, "Unexpected SMB2 session identifier.");
                            TestAssertions.SequenceEqual(
                                new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F },
                                parsed.Signature,
                                "Unexpected SMB2 signature.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "Smb2002HeaderAllowsReservedCreditCharge",
                        displayName: "SMB 2.0.2 headers allow the reserved CreditCharge field to remain zero",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header header = CreateValidSmb2Header();
                            header.CreditCharge = 0;
                            header.Command = Smb2Command.Negotiate;
                            header.CreditRequest = 3;
                            header.Flags = Smb2HeaderFlags.None;
                            header.NextCommand = 0;
                            header.MessageId = 0;
                            header.ProcessId = 0;
                            header.TreeId = 0;
                            header.SessionId = 0;
                            header.Signature = new byte[16];

                            Smb2Header parsed = Smb2Header.ReadFrom(header.ToByteArray());
                            Smb2HeaderValidator.Validate(parsed);
                            TestAssertions.Equal((ushort)0, parsed.CreditCharge, "Expected SMB 2.0.2 headers to preserve a reserved CreditCharge value of zero.");
                            TestAssertions.Equal((ushort)3, parsed.CreditRequest, "Unexpected SMB2 credit request value.");
                            TestAssertions.Equal(0UL, parsed.MessageId, "Unexpected SMB2 message identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "HeaderReadersRejectMalformedInputs",
                        displayName: "SMB header readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1Header.ReadFrom(new byte[31]),
                                "A truncated SMB1 header should fail to parse.");

                            Smb1Header invalidSmb1Header = CreateValidSmb1Header();
                            invalidSmb1Header.Flags = (Smb1HeaderFlags)0x01;
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb1HeaderValidator.Validate(invalidSmb1Header),
                                "Unsupported SMB1 flag bits should fail validation.");

                            byte[] invalidSmb2Bytes = CreateValidSmb2Header().ToByteArray();
                            invalidSmb2Bytes[4] = 0x20;
                            invalidSmb2Bytes[5] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2Header.ReadFrom(invalidSmb2Bytes),
                                "An SMB2 header with the wrong structure size should fail to parse.");

                            Smb2Header invalidSmb2Header = CreateValidSmb2Header();
                            invalidSmb2Header.NextCommand = 4;
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2HeaderValidator.Validate(invalidSmb2Header),
                                "A misaligned SMB2 next-command offset should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
