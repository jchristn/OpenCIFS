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
    internal static class Smb2SessionTreeSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2SessionTree",
                displayName: "SMB2 session and tree messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2SessionTree",
                        caseId: "Smb2SessionAndTreeMessagesRoundTrip",
                        displayName: "SMB2 session, tree, and internal auth tokens round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsNtlmNegotiateToken negotiateToken = new OpenCifsNtlmNegotiateToken
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP"
                            };
                            byte[] negotiateTokenBytes = negotiateToken.ToByteArray();
                            OpenCifsNtlmNegotiateToken parsedNegotiateToken = OpenCifsNtlmNegotiateToken.ReadFrom(negotiateTokenBytes);
                            TestAssertions.Equal("alice", parsedNegotiateToken.UserName, "The internal NTLM negotiate token user name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedNegotiateToken.UserDomain, "The internal NTLM negotiate token domain changed.");

                            Smb2SessionSetupRequest sessionSetupRequest = new Smb2SessionSetupRequest
                            {
                                Flags = 0,
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.None,
                                Channel = 0,
                                PreviousSessionId = 0,
                                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenInit(new SpnegoNegTokenInit
                                {
                                    MechanismTypes = new string[] { SpnegoMechanismOid.Ntlm },
                                    MechanismToken = negotiateTokenBytes
                                })
                            };

                            Smb2SessionSetupRequestValidator.Validate(sessionSetupRequest);
                            byte[] encodedSessionSetupRequest = sessionSetupRequest.ToByteArray();
                            Smb2SessionSetupRequest parsedSessionSetupRequest = Smb2SessionSetupRequest.ReadFrom(encodedSessionSetupRequest);
                            Smb2SessionSetupRequestValidator.Validate(parsedSessionSetupRequest);
                            TestAssertions.Equal(sessionSetupRequest.SecurityMode, parsedSessionSetupRequest.SecurityMode, "The SMB2 session-setup request security mode changed.");

                            Smb2SessionSetupRequest signingRequiredOnlyRequest = new Smb2SessionSetupRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningRequired,
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            Smb2SessionSetupRequestValidator.Validate(signingRequiredOnlyRequest);

                            SpnegoNegTokenInit parsedInitToken = SpnegoTokenCodec.DecodeNegTokenInit(parsedSessionSetupRequest.SecurityBuffer);
                            OpenCifsNtlmNegotiateToken parsedInitMechanismToken = OpenCifsNtlmNegotiateToken.ReadFrom(parsedInitToken.MechanismToken!);
                            TestAssertions.Equal("alice", parsedInitMechanismToken.UserName, "The session-setup request mechanism token user name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedInitMechanismToken.UserDomain, "The session-setup request mechanism token domain changed.");

                            OpenCifsNtlmChallengeToken challengeToken = new OpenCifsNtlmChallengeToken
                            {
                                ServerChallenge = Hex("0123456789ABCDEF"),
                                ServerName = "LAB-SERVER",
                                TargetDomain = "WORKGROUP"
                            };
                            byte[] challengeTokenBytes = challengeToken.ToByteArray();
                            OpenCifsNtlmChallengeToken parsedChallengeToken = OpenCifsNtlmChallengeToken.ReadFrom(challengeTokenBytes);
                            TestAssertions.SequenceEqual(Hex("0123456789ABCDEF"), parsedChallengeToken.ServerChallenge, "The internal NTLM challenge token challenge bytes changed.");
                            TestAssertions.Equal("LAB-SERVER", parsedChallengeToken.ServerName, "The internal NTLM challenge token server name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedChallengeToken.TargetDomain, "The internal NTLM challenge token target domain changed.");

                            Smb2SessionSetupResponse sessionSetupResponse = new Smb2SessionSetupResponse
                            {
                                SessionFlags = Smb2SessionFlags.None,
                                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                                {
                                    NegotiationState = SpnegoNegState.AcceptIncomplete,
                                    SupportedMechanism = SpnegoMechanismOid.Ntlm,
                                    ResponseToken = challengeTokenBytes
                                })
                            };

                            Smb2SessionSetupResponseValidator.Validate(sessionSetupResponse);
                            byte[] encodedSessionSetupResponse = sessionSetupResponse.ToByteArray();
                            Smb2SessionSetupResponse parsedSessionSetupResponse = Smb2SessionSetupResponse.ReadFrom(encodedSessionSetupResponse);
                            Smb2SessionSetupResponseValidator.Validate(parsedSessionSetupResponse);
                            SpnegoNegTokenResp parsedChallengeResponse = SpnegoTokenCodec.DecodeNegTokenResp(parsedSessionSetupResponse.SecurityBuffer);
                            OpenCifsNtlmChallengeToken parsedChallengeMechanismToken = OpenCifsNtlmChallengeToken.ReadFrom(parsedChallengeResponse.ResponseToken!);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, parsedChallengeResponse.NegotiationState!.Value, "The session-setup response negotiation state changed.");
                            TestAssertions.Equal("LAB-SERVER", parsedChallengeMechanismToken.ServerName, "The session-setup response mechanism token server name changed.");

                            OpenCifsNtlmAuthenticateToken authenticateToken = new OpenCifsNtlmAuthenticateToken
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP",
                                NtChallengeResponse = Hex("00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F10"),
                                LmChallengeResponse = Hex("FFEEDDCCBBAA998877665544332211000102030405060708")
                            };
                            byte[] authenticateTokenBytes = authenticateToken.ToByteArray();
                            OpenCifsNtlmAuthenticateToken parsedAuthenticateToken = OpenCifsNtlmAuthenticateToken.ReadFrom(authenticateTokenBytes);
                            TestAssertions.Equal("alice", parsedAuthenticateToken.UserName, "The internal NTLM authenticate token user name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedAuthenticateToken.UserDomain, "The internal NTLM authenticate token domain changed.");
                            TestAssertions.SequenceEqual(authenticateToken.NtChallengeResponse, parsedAuthenticateToken.NtChallengeResponse, "The internal NTLM authenticate token NT response changed.");
                            TestAssertions.SequenceEqual(authenticateToken.LmChallengeResponse, parsedAuthenticateToken.LmChallengeResponse, "The internal NTLM authenticate token LM response changed.");

                            Smb2TreeConnectRequest treeConnectRequest = new Smb2TreeConnectRequest
                            {
                                Flags = 0,
                                Path = "\\\\LAB-SERVER\\share"
                            };

                            Smb2TreeConnectRequestValidator.Validate(treeConnectRequest);
                            byte[] encodedTreeConnectRequest = treeConnectRequest.ToByteArray();
                            Smb2TreeConnectRequest parsedTreeConnectRequest = Smb2TreeConnectRequest.ReadFrom(encodedTreeConnectRequest);
                            Smb2TreeConnectRequestValidator.Validate(parsedTreeConnectRequest);
                            TestAssertions.Equal("\\\\LAB-SERVER\\share", parsedTreeConnectRequest.Path, "The SMB2 tree-connect path changed.");

                            Smb2TreeConnectResponse treeConnectResponse = new Smb2TreeConnectResponse
                            {
                                ShareType = Smb2ShareType.Disk,
                                ShareFlags = 0x00000003,
                                Capabilities = 0x00000008,
                                MaximalAccess = 0x001F01FF
                            };

                            Smb2TreeConnectResponseValidator.Validate(treeConnectResponse);
                            byte[] encodedTreeConnectResponse = treeConnectResponse.ToByteArray();
                            Smb2TreeConnectResponse parsedTreeConnectResponse = Smb2TreeConnectResponse.ReadFrom(encodedTreeConnectResponse);
                            Smb2TreeConnectResponseValidator.Validate(parsedTreeConnectResponse);
                            TestAssertions.Equal(Smb2ShareType.Disk, parsedTreeConnectResponse.ShareType, "The SMB2 tree-connect response share type changed.");
                            TestAssertions.Equal(0x001F01FFU, parsedTreeConnectResponse.MaximalAccess, "The SMB2 tree-connect response maximal access changed.");

                            Smb2TreeDisconnectRequest treeDisconnectRequest = new Smb2TreeDisconnectRequest();
                            byte[] encodedTreeDisconnectRequest = treeDisconnectRequest.ToByteArray();
                            Smb2TreeDisconnectRequest parsedTreeDisconnectRequest = Smb2TreeDisconnectRequest.ReadFrom(encodedTreeDisconnectRequest);
                            Smb2TreeDisconnectRequestValidator.Validate(parsedTreeDisconnectRequest);

                            Smb2TreeDisconnectResponse treeDisconnectResponse = new Smb2TreeDisconnectResponse();
                            byte[] encodedTreeDisconnectResponse = treeDisconnectResponse.ToByteArray();
                            Smb2TreeDisconnectResponse parsedTreeDisconnectResponse = Smb2TreeDisconnectResponse.ReadFrom(encodedTreeDisconnectResponse);
                            Smb2TreeDisconnectResponseValidator.Validate(parsedTreeDisconnectResponse);

                            Smb2LogoffRequest logoffRequest = new Smb2LogoffRequest();
                            byte[] encodedLogoffRequest = logoffRequest.ToByteArray();
                            Smb2LogoffRequest parsedLogoffRequest = Smb2LogoffRequest.ReadFrom(encodedLogoffRequest);
                            Smb2LogoffRequestValidator.Validate(parsedLogoffRequest);

                            Smb2LogoffResponse logoffResponse = new Smb2LogoffResponse();
                            byte[] encodedLogoffResponse = logoffResponse.ToByteArray();
                            Smb2LogoffResponse parsedLogoffResponse = Smb2LogoffResponse.ReadFrom(encodedLogoffResponse);
                            Smb2LogoffResponseValidator.Validate(parsedLogoffResponse);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2SessionTree",
                        caseId: "Smb2SessionAndTreeMessagesRejectMalformedInputs",
                        displayName: "SMB2 session, tree, and internal auth token codecs reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2SessionSetupRequest invalidSessionSetupRequest = new Smb2SessionSetupRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            byte[] invalidSessionSetupRequestBytes = invalidSessionSetupRequest.ToByteArray();
                            invalidSessionSetupRequestBytes[12] = 0x44;
                            invalidSessionSetupRequestBytes[13] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2SessionSetupRequest.ReadFrom(invalidSessionSetupRequestBytes),
                                "An SMB2 session-setup request with an invalid security-buffer offset should fail to parse.");

                            Smb2SessionSetupRequest emptySecurityBufferRequest = new Smb2SessionSetupRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                SecurityBuffer = Array.Empty<byte>()
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2SessionSetupRequestValidator.Validate(emptySecurityBufferRequest),
                                "An SMB2 session-setup request without a security buffer should fail validation.");

                            Smb2SessionSetupResponse invalidSessionSetupResponse = new Smb2SessionSetupResponse
                            {
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            byte[] invalidSessionSetupResponseBytes = invalidSessionSetupResponse.ToByteArray();
                            invalidSessionSetupResponseBytes[4] = 0x44;
                            invalidSessionSetupResponseBytes[5] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2SessionSetupResponse.ReadFrom(invalidSessionSetupResponseBytes),
                                "An SMB2 session-setup response with an invalid security-buffer offset should fail to parse.");

                            Smb2TreeConnectRequest invalidTreeConnectRequest = new Smb2TreeConnectRequest
                            {
                                Path = "\\\\LAB-SERVER\\share"
                            };
                            byte[] invalidTreeConnectRequestBytes = invalidTreeConnectRequest.ToByteArray();
                            invalidTreeConnectRequestBytes[6] = 0x03;
                            invalidTreeConnectRequestBytes[7] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2TreeConnectRequest.ReadFrom(invalidTreeConnectRequestBytes),
                                "An SMB2 tree-connect request with an odd path length should fail to parse.");

                            Smb2TreeConnectResponse invalidTreeConnectResponse = new Smb2TreeConnectResponse
                            {
                                ShareType = (Smb2ShareType)0x7F
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2TreeConnectResponseValidator.Validate(invalidTreeConnectResponse),
                                "An SMB2 tree-connect response with an unknown share type should fail validation.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2TreeDisconnectRequest.ReadFrom(new byte[3]),
                                "A truncated SMB2 tree-disconnect request should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2TreeDisconnectResponse.ReadFrom(new byte[3]),
                                "A truncated SMB2 tree-disconnect response should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LogoffRequest.ReadFrom(new byte[3]),
                                "A truncated SMB2 logoff request should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LogoffResponse.ReadFrom(new byte[3]),
                                "A truncated SMB2 logoff response should fail to parse.");

                            byte[] authenticateTokenBytes = new OpenCifsNtlmAuthenticateToken
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP",
                                NtChallengeResponse = Hex("00112233445566778899AABBCCDDEEFF"),
                                LmChallengeResponse = Hex("FFEEDDCCBBAA99887766554433221100")
                            }.ToByteArray();
                            byte[] malformedAuthenticateTokenBytes = Combine(authenticateTokenBytes, new byte[] { 0x00 });
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => OpenCifsNtlmAuthenticateToken.ReadFrom(malformedAuthenticateTokenBytes),
                                "An internal NTLM authenticate token with trailing bytes should fail to parse.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
