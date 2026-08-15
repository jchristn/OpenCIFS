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
    internal static class FrameFoundationSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Frames",
                displayName: "Frame header foundations",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Frames",
                        caseId: "DirectTcpHeaderRoundTrip",
                        displayName: "Direct TCP frame headers round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            DirectTcpFrameHeader header = new DirectTcpFrameHeader
                            {
                                Length = 4096
                            };

                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(DirectTcpFrameHeader.Size, encoded.Length, "Unexpected Direct TCP header length.");

                            DirectTcpFrameHeader parsed = DirectTcpFrameHeader.ReadFrom(encoded);
                            DirectTcpFrameValidator.Validate(parsed);
                            TestAssertions.Equal(4096, parsed.Length, "Unexpected Direct TCP payload length.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Frames",
                        caseId: "NetBiosHeaderRoundTrip",
                        displayName: "NetBIOS session service headers round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
                            {
                                MessageType = NetBiosSessionMessageType.SessionKeepAlive,
                                Length = 1024
                            };

                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(NetBiosSessionServiceHeader.Size, encoded.Length, "Unexpected NetBIOS header length.");

                            NetBiosSessionServiceHeader parsed = NetBiosSessionServiceHeader.ReadFrom(encoded);
                            NetBiosSessionServiceValidator.Validate(parsed);
                            TestAssertions.Equal(NetBiosSessionMessageType.SessionKeepAlive, parsed.MessageType, "Unexpected NetBIOS message type.");
                            TestAssertions.Equal(1024, parsed.Length, "Unexpected NetBIOS payload length.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Frames",
                        caseId: "FrameHeadersRejectMalformedInputs",
                        displayName: "Frame header readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DirectTcpFrameHeader.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "A truncated Direct TCP header should fail to parse.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => DirectTcpFrameValidator.Validate(null!),
                                "A null Direct TCP header should fail validation.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosSessionServiceHeader.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "A truncated NetBIOS header should fail to parse.");

                            NetBiosSessionServiceHeader invalidHeader = new NetBiosSessionServiceHeader
                            {
                                MessageType = (NetBiosSessionMessageType)0x7F,
                                Length = 1
                            };

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => NetBiosSessionServiceValidator.Validate(invalidHeader),
                                "An unknown NetBIOS message type should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
