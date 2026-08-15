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
    internal static class ServerEchoSuiteBuilder
    {
        /// <summary>
        /// Build the server echo suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ServerEchoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Echo",
                displayName: "Server echo handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Echo",
                        caseId: "ServerAcceptsAuthenticatedEchoAndRejectsUnknownSession",
                        displayName: "Server accepts authenticated echo requests and rejects unknown sessions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);

                            OpenCifsServerOperationResult<Smb2EchoResponse> successResult = host.HandleEcho(sessionId, new Smb2EchoRequest());
                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected authenticated SMB2 echo to succeed.");
                            Smb2EchoResponseValidator.Validate(successResult.Response);

                            OpenCifsServerOperationResult<Smb2EchoResponse> missingSessionResult = host.HandleEcho(sessionId + 1, new Smb2EchoRequest());
                            TestAssertions.Equal(NtStatus.AccessDenied, missingSessionResult.Status, "Expected SMB2 echo to reject unknown sessions in the bounded session-backed slice.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Echo",
                        caseId: "ServerRejectsNullEchoRequest",
                        displayName: "Server rejects null echo requests through the validator surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleEcho(sessionId, null!),
                                "A null SMB2 echo request should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
