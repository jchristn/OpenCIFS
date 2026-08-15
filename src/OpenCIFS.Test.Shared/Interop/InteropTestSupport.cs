namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.IO;
    using System.Text;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;

    internal static class InteropTestSupport
    {
        internal static OpenCifsServerHost CreateServerHost(string? sharePath = null, OpenCifsServerSharedState? sharedState = null, SmbDialect maximumDialect = SmbDialect.Smb21, bool requireEncryptionForSmb3 = true)
        {
            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
            {
                ServerName = TestEnvironmentDefaults.DefaultServerName,
                MaximumDialect = maximumDialect,
                RequireEncryptionForSmb3 = requireEncryptionForSmb3
            }, sharedState);
            host.RegisterShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = sharePath ?? "SampleShare",
                CreateRootIfMissing = true
            });
            host.RegisterAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });
            return host;
        }

        internal static ulong AuthenticateLoopbackSession(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential)
        {
            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                credential,
                challengeResult.SessionId,
                challengeResult.Status,
                challengeResult.Response);
            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);
            return successResult.SessionId;
        }

        internal static uint AuthenticateLoopbackSessionAndTree(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential)
        {
            ulong sessionId = AuthenticateLoopbackSession(server, client, credential);

            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest(TestEnvironmentDefaults.DefaultShareName);
            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(sessionId, treeConnectRequest);
            client.ApplyTreeConnectResult(TestEnvironmentDefaults.DefaultShareName, treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);
            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree before loopback file operations.");
            return treeConnectResult.TreeId;
        }

        internal static uint AuthenticateLoopbackSessionAndTreeWithHeaders(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential, ushort creditRequest)
        {
            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest);

            Smb2Header treeConnectHeader = client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId);
            Smb2TreeConnectRequest treeConnectRequest = client.CreateTreeConnectRequest(TestEnvironmentDefaults.DefaultShareName);
            server.ValidateAndAcceptRequestHeader(treeConnectHeader, Smb2Command.TreeConnect, expectedSessionId: sessionId);
            OpenCifsServerTreeConnectResult treeConnectResult = server.HandleTreeConnect(sessionId, treeConnectRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(treeConnectHeader, treeConnectResult.Status, sessionId: sessionId, treeId: treeConnectResult.TreeId));
            client.ApplyTreeConnectResult(TestEnvironmentDefaults.DefaultShareName, treeConnectResult.TreeId, treeConnectResult.Status, treeConnectResult.Response);

            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree before compounded loopback file operations.");
            TestAssertions.Equal(creditRequest, (ushort)client.AvailableCredits, "Expected header-wrapped authenticate and tree setup to preserve the negotiated client credit window.");
            TestAssertions.Equal(creditRequest, (ushort)server.AvailableCredits, "Expected header-wrapped authenticate and tree setup to preserve the negotiated server credit window.");
            return treeConnectResult.TreeId;
        }

        internal static uint AuthenticateEncryptedLoopbackSessionAndTree(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential, ushort creditRequest = 4)
        {
            ulong sessionId = AuthenticateLoopbackSessionWithHeaders(server, client, credential, creditRequest);
            TestAssertions.True(client.IsSessionEncryptionRequired, "Expected the authenticated SMB3 loopback session to require encryption before tree connect.");

            Smb2CompoundPacket treeConnectResponsePacket = RoundTripEncryptedPacket(
                server,
                client,
                new Smb2CompoundPacket(new[]
                {
                    new Smb2CompoundPacketEntry(
                        client.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: sessionId),
                        client.CreateTreeConnectRequest(TestEnvironmentDefaults.DefaultShareName).ToByteArray())
                }),
                "encrypted tree connect");

            Smb2CompoundPacketEntry treeConnectResponseEntry = treeConnectResponsePacket.Entries[0];
            client.ApplyTreeConnectResult(
                TestEnvironmentDefaults.DefaultShareName,
                treeConnectResponseEntry.Header.TreeId,
                treeConnectResponseEntry.Header.Status,
                Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(treeConnectResponseEntry.Header.Command, treeConnectResponseEntry.Payload)));

            TestAssertions.Equal(1, client.ConnectedTreeIds.Length, "Expected a connected tree before encrypted loopback file operations.");
            return treeConnectResponseEntry.Header.TreeId;
        }

        internal static ulong AuthenticateLoopbackSessionWithHeaders(OpenCifsServerHost server, OpenCifsClientSession client, OpenCifsClientCredential credential, ushort creditRequest)
        {
            Smb2Header negotiateHeader = client.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: creditRequest);
            Smb2NegotiateRequest negotiateRequest = client.CreateNegotiateRequest();
            server.ValidateAndAcceptRequestHeader(negotiateHeader, Smb2Command.Negotiate);
            Smb2NegotiateResponse negotiateResponse = server.HandleNegotiate(negotiateRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(negotiateHeader, NtStatus.Success));
            client.ApplyNegotiateResponse(negotiateResponse);

            Smb2Header initialSessionHeader = client.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: 0);
            Smb2SessionSetupRequest initialSessionRequest = client.CreateSessionSetupRequest(credential);
            server.ValidateAndAcceptRequestHeader(initialSessionHeader, Smb2Command.SessionSetup);
            OpenCifsServerSessionSetupResult challengeResult = server.HandleSessionSetup(0, initialSessionRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(initialSessionHeader, challengeResult.Status, sessionId: challengeResult.SessionId));

            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                credential,
                challengeResult.SessionId,
                challengeResult.Status,
                challengeResult.Response);
            Smb2Header authenticateSessionHeader = client.CreateRequestHeader(Smb2Command.SessionSetup, sessionId: challengeResult.SessionId);
            server.ValidateAndAcceptRequestHeader(authenticateSessionHeader, Smb2Command.SessionSetup, expectedSessionId: challengeResult.SessionId);
            OpenCifsServerSessionSetupResult successResult = server.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
            client.ApplyResponseHeader(server.CreateResponseHeader(authenticateSessionHeader, successResult.Status, sessionId: successResult.SessionId));
            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);

            TestAssertions.Equal(creditRequest, (ushort)client.AvailableCredits, "Expected header-wrapped session setup to preserve the negotiated client credit window.");
            TestAssertions.Equal(creditRequest, (ushort)server.AvailableCredits, "Expected header-wrapped session setup to preserve the negotiated server credit window.");
            return successResult.SessionId;
        }

        internal static OpenCifsClientSession CreateNegotiatedClient(OpenCifsServerHost server, Guid? clientGuid = null, SmbDialect maximumDialect = SmbDialect.Smb21, bool preferEncryption = true)
        {
            OpenCifsClientSession client = CreateClient(clientGuid, maximumDialect, preferEncryption);
            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
            Smb2NegotiateResponse response = server.HandleNegotiate(request);
            client.ApplyNegotiateResponse(response);
            return client;
        }

        internal static OpenCifsClientSession CreateClient(Guid? clientGuid = null, SmbDialect maximumDialect = SmbDialect.Smb21, bool preferEncryption = true)
        {
            return new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = TestEnvironmentDefaults.DefaultServerName,
                MaximumDialect = maximumDialect,
                PreferEncryption = preferEncryption
            }, clientGuid);
        }

        internal static Smb2CompoundPacket RoundTripEncryptedPacket(OpenCifsServerHost server, OpenCifsClientSession client, Smb2CompoundPacket requestPacket, string operationLabel)
        {
            byte[] encryptedRequestBytes = client.FinalizeRequestPacket(requestPacket);
            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedRequestBytes), "Expected " + operationLabel + " requests to use an SMB3 transform header.");

            byte[] decryptedRequestBytes = server.UnwrapRequestPacket(encryptedRequestBytes, out bool wasEncrypted);
            TestAssertions.True(wasEncrypted, "Expected the server to recognize the encrypted " + operationLabel + " request.");

            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(decryptedRequestBytes);
            server.ValidateRequestPacket(parsedRequestPacket, decryptedRequestBytes, wasEncrypted);

            Smb2CompoundPacket responsePacket = server.HandleCompoundRequestPacket(parsedRequestPacket);
            byte[] encryptedResponseBytes = server.FinalizeResponsePacket(responsePacket);
            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedResponseBytes), "Expected " + operationLabel + " responses to use an SMB3 transform header.");

            byte[] decryptedResponseBytes = client.UnwrapResponsePacket(encryptedResponseBytes);
            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(decryptedResponseBytes);
            client.ValidateResponsePacket(parsedResponsePacket, decryptedResponseBytes);
            client.ApplyCompoundResponsePacket(parsedResponsePacket);
            return parsedResponsePacket;
        }

        internal static OpenCifsClientCredential CreateCredential()
        {
            return new OpenCifsClientCredential
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            };
        }

        internal static byte[] CreateLargePayloadBytes(int length)
        {
            if (length <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be positive.");
            }

            byte[] bytes = new byte[length];

            for (int index = 0; index < bytes.Length; index++)
            {
                bytes[index] = unchecked((byte)('a' + (index % 19)));
            }

            return bytes;
        }

        internal static void DeleteDirectoryForcefully(string rootPath)
        {
            TestPathUtilities.DeleteDirectoryForcefully(rootPath);
        }    }
}