namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Sample.OpenCifsServer;
    using Touchstone.Core;
    using static OpenCIFS.Server.Tests.Shared.ServerTestSupport;
    internal static class ServerNegotiationDirectTcpCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerBridgesSmb1MultiProtocolNegotiateToSmb2",
                        displayName: "Direct-TCP server bridges SMB1 multi-protocol negotiate into an SMB2 negotiate response",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb1NegotiateRequest request = new Smb1NegotiateRequest
                                {
                                    Header = new Smb1Header
                                    {
                                        Command = Smb1Command.Negotiate,
                                        Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.CanonicalizedPaths,
                                        Flags2 = Smb1HeaderFlags2.LongNames | Smb1HeaderFlags2.Unicode,
                                        ProcessIdHigh = 0x1357,
                                        ProcessIdLow = 0x2468,
                                        MultiplexId = 1
                                    },
                                    Dialects = new string[]
                                    {
                                        "NT LM 0.12",
                                        Smb1NegotiateRequest.Smb2002DialectString,
                                        Smb1NegotiateRequest.Smb2WildcardDialectString
                                    }
                                };

                                await WriteDirectTcpFrameAsync(stream, request.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);

                                TestAssertions.Equal(1, responsePacket.Entries.Count, "Expected a single SMB2 negotiate response entry.");
                                TestAssertions.Equal(Smb2Command.Negotiate, responsePacket.Entries[0].Header.Command, "Expected the bridged response command to be SMB2 negotiate.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the bridged response status to be success.");
                                TestAssertions.Equal(0UL, responsePacket.Entries[0].Header.MessageId, "Expected the bridged SMB2 negotiate response to remain bound to sequence number zero.");

                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);
                                TestAssertions.Equal(SmbDialect.Smb21, response.Dialect, "Expected the bridged SMB1 negotiate request to resolve to the highest implemented SMB 2.x dialect.");
                                TestAssertions.True((response.SecurityMode & Smb2SecurityMode.SigningEnabled) != 0, "Expected the bridged SMB2 negotiate response to keep signing enabled.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerBridgesSmb1MultiProtocolNegotiateToOptInSmb302",
                        displayName: "Direct-TCP server bridges SMB1 multi-protocol negotiate into an opt-in SMB 3.0.2 negotiate response",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                port,
                                requireEncryptionForSmb3: false,
                                token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb1NegotiateRequest request = new Smb1NegotiateRequest
                                {
                                    Header = new Smb1Header
                                    {
                                        Command = Smb1Command.Negotiate,
                                        Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.CanonicalizedPaths,
                                        Flags2 = Smb1HeaderFlags2.LongNames | Smb1HeaderFlags2.Unicode,
                                        ProcessIdHigh = 0x1357,
                                        ProcessIdLow = 0x2468,
                                        MultiplexId = 1
                                    },
                                    Dialects = new string[]
                                    {
                                        "NT LM 0.12",
                                        Smb1NegotiateRequest.Smb2002DialectString,
                                        Smb1NegotiateRequest.Smb2WildcardDialectString
                                    }
                                };

                                await WriteDirectTcpFrameAsync(stream, request.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);

                                TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the opt-in bridged SMB1 negotiate request to resolve to SMB 3.0.2.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerNegotiatesRequiredEncryptionSmb302ForSmb311StyleRequestShape",
                        displayName: "Direct-TCP server negotiates required-encryption SMB 3.0.2 for an SMB 3.1.1-style request shape",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(
                                port,
                                requireEncryptionForSmb3: true,
                                token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb2NegotiateRequest request = new Smb2NegotiateRequest
                                {
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                    ClientGuid = Guid.NewGuid(),
                                    Dialects = new[] { SmbDialect.Smb302, SmbDialect.Smb311 },
                                    NegotiateContextCount = 1,
                                    NegotiateContextData = new byte[]
                                    {
                                        0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                                    }
                                };
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2),
                                            request.ToByteArray())
                                    });

                                await WriteDirectTcpFrameAsync(stream, requestPacket.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);

                                TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the required-encryption direct-TCP server to accept the SMB 3.1.1-style request shape and negotiate SMB 3.0.2.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerRejectsSmb1NegotiateWithoutSmb2002Dialect",
                        displayName: "Direct-TCP server closes the connection when an SMB1 multi-protocol negotiate omits SMB 2.002",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            DirectTcpServerHandle serverHandle = await StartDirectTcpServerAsync(port, token).ConfigureAwait(false);
                            CancellationTokenSource serverCancellationTokenSource = serverHandle.CancellationTokenSource;
                            Task serverTask = serverHandle.ServerTask;

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb1NegotiateRequest request = new Smb1NegotiateRequest
                                {
                                    Dialects = new string[]
                                    {
                                        "NT LM 0.12"
                                    }
                                };

                                await WriteDirectTcpFrameAsync(stream, request.ToByteArray(), token).ConfigureAwait(false);
                                byte[]? responsePayload = await TryReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);

                                if (responsePayload != null)
                                {
                                    throw new InvalidOperationException("Expected the direct-TCP server to close the connection without responding when SMB 2.002 is absent from the SMB1 negotiate preamble.");
                                }
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        })
            };
        }
    }
}

