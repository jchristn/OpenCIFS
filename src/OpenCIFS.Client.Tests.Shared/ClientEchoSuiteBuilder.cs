namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;
    internal static class ClientEchoSuiteBuilder
    {
        /// <summary>
        /// Build the client echo suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Echo",
                displayName: "Client echo handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Echo",
                        caseId: "ClientBuildsEchoRequestsAndAcceptsSuccessfulResponses",
                        displayName: "Client builds authenticated echo requests and accepts successful responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient();
                            Smb2EchoRequest echoRequest = session.CreateEchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            session.ApplyEchoResult(NtStatus.Success, new Smb2EchoResponse());

                            TestAssertions.True(session.IsAuthenticated, "Expected echo handling to preserve authenticated client state.");
                            TestAssertions.True(session.SessionId == 9, "Expected echo handling to preserve the authenticated session identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Echo",
                        caseId: "ClientRejectsEchoBeforeAuthenticationOrOnFailureStatus",
                        displayName: "Client rejects echo use before authentication and rejects failed echo results",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession unauthenticatedSession = CreateNegotiatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => unauthenticatedSession.CreateEchoRequest(),
                                "An authenticated session should be required before building SMB2 echo requests.");

                            OpenCifsClientSession authenticatedSession = CreateAuthenticatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => authenticatedSession.ApplyEchoResult(NtStatus.AccessDenied, new Smb2EchoResponse()),
                                "A failed SMB2 echo response should be rejected by the client.");
                            TestAssertions.Throws<ArgumentNullException>(
                                () => authenticatedSession.ApplyEchoResult(NtStatus.Success, null!),
                                "A null SMB2 echo response should be rejected by the client.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
