namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class InteropLoopbackEchoSuiteBuilder
    {
        /// <summary>
        /// Build the loopback SMB2 credit and header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor LoopbackEchoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackEcho",
                displayName: "Loopback echo coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackEcho",
                        caseId: "ClientAndServerCompleteAuthenticatedEchoWithHeaders",
                        displayName: "Client and server loopback complete an authenticated header-wrapped SMB2 echo",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            server.ValidateAndAcceptRequestHeader(echoHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(sessionId, echoRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(echoHeader, echoResult.Status, sessionId: sessionId));
                            client.ApplyEchoResult(echoResult.Status, echoResult.Response);

                            TestAssertions.True(client.IsAuthenticated, "Expected loopback echo to preserve authenticated client state.");
                            TestAssertions.True(client.SessionId == sessionId, "Expected loopback echo to preserve the authenticated session identifier.");
                            TestAssertions.Equal(1, client.AvailableCredits, "Expected loopback echo to preserve the bounded client credit window.");
                            TestAssertions.Equal(1, server.AvailableCredits, "Expected loopback echo to preserve the bounded server credit window.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackEcho",
                        caseId: "ClientAndServerRejectEchoForUnknownSession",
                        displayName: "Client and server loopback reject echo requests for an unknown session",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost();
                            OpenCifsClientSession client = CreateNegotiatedClient(server);
                            OpenCifsClientCredential credential = CreateCredential();
                            ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

                            Smb2Header echoHeader = client.CreateRequestHeader(Smb2Command.Echo, sessionId: sessionId);
                            Smb2EchoRequest echoRequest = client.CreateEchoRequest();
                            server.ValidateAndAcceptRequestHeader(echoHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = server.HandleEcho(sessionId + 1, echoRequest);
                            client.ApplyResponseHeader(server.CreateResponseHeader(echoHeader, echoResult.Status, sessionId: sessionId + 1));

                            TestAssertions.Throws<InvalidOperationException>(
                                () => client.ApplyEchoResult(echoResult.Status, echoResult.Response),
                                "Expected loopback echo coverage to reject unknown sessions.");
                            return Task.CompletedTask;
                        })
                });
        }

    }
}

