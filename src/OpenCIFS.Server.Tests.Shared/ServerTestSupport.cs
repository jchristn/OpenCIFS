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

    internal static class ServerTestSupport
    {
        internal static OpenCifsServerHost CreateServerHost(string? sharePath = null, OpenCifsServerRequestCallbacks? callbacks = null, OpenCifsServerSharedState? sharedState = null, bool requireEncryptionForSmb3 = true)
        {
            OpenCifsServerOptions options = new OpenCifsServerOptions
            {
                ServerName = TestEnvironmentDefaults.DefaultServerName,
                RequireEncryptionForSmb3 = requireEncryptionForSmb3
            };
            options.RequestCallbacks = callbacks;
            OpenCifsServerHost host = new OpenCifsServerHost(options, sharedState);
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

        internal static void RegisterDefaultShareAndAccount(OpenCifsServerHost host, string sharePath)
        {
            host.RegisterShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = sharePath,
                CreateRootIfMissing = true
            });
            host.RegisterAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });
        }

        internal static Smb2CreateRequest CreateDurableCreateRequest(string path)
        {
            return new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.Batch,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0010000U,
                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.Open,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = path,
                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                {
                    Smb2DurableHandleRequestContext.Create()
                })
            };
        }

        internal static Smb2CreateRequest CreateDurableHandleV2CreateRequest(string path, Guid createGuid, Smb2DurableHandleFlags flags = Smb2DurableHandleFlags.None)
        {
            return new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.Batch,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0010000U,
                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.Open,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = path,
                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                {
                    new Smb2DurableHandleRequestV2Context
                    {
                        Timeout = 0,
                        Flags = flags,
                        CreateGuid = createGuid
                    }.ToCreateContext()
                })
            };
        }

        internal static Smb2CreateRequest CreateDurableLeaseCreateRequest(string path, byte[] leaseKey, Smb2LeaseState leaseState)
        {
            return new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.Lease,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0010000U,
                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.Open,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = path,
                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                {
                    Smb2DurableHandleRequestContext.Create(),
                    new Smb2CreateRequestLeaseContext
                    {
                        LeaseKey = leaseKey,
                        LeaseState = leaseState
                    }.ToCreateContext()
                })
            };
        }

        internal static Smb2CreateRequest CreateDurableReconnectCreateRequest(string path, ulong persistentFileId, ulong volatileFileId)
        {
            return new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.Batch,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0010000U,
                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.Open,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = path,
                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                {
                    new Smb2DurableHandleReconnectContext
                    {
                        PersistentFileId = persistentFileId,
                        VolatileFileId = volatileFileId
                    }.ToCreateContext()
                })
            };
        }

        internal static Smb2CreateRequest CreateDurableHandleV2ReconnectCreateRequest(string path, ulong persistentFileId, ulong volatileFileId, Guid createGuid, Smb2DurableHandleFlags flags = Smb2DurableHandleFlags.None)
        {
            return new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.Batch,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0010000U,
                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.Open,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = path,
                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                {
                    new Smb2DurableHandleReconnectV2Context
                    {
                        PersistentFileId = persistentFileId,
                        VolatileFileId = volatileFileId,
                        CreateGuid = createGuid,
                        Flags = flags
                    }.ToCreateContext()
                })
            };
        }

        internal static Smb2CreateRequest CreateDurableLeaseReconnectCreateRequest(
            string path,
            ulong persistentFileId,
            ulong volatileFileId,
            byte[] leaseKey,
            Smb2LeaseState leaseState)
        {
            return new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.Lease,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0010000U,
                FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.Open,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = path,
                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                {
                    new Smb2DurableHandleReconnectContext
                    {
                        PersistentFileId = persistentFileId,
                        VolatileFileId = volatileFileId
                    }.ToCreateContext(),
                    new Smb2CreateRequestLeaseContext
                    {
                        LeaseKey = leaseKey,
                        LeaseState = leaseState
                    }.ToCreateContext()
                })
            };
        }

        internal static ulong AuthenticateSession(OpenCifsServerHost host)
        {
            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest(TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultUserDomain));
            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(
                challengeResult.SessionId,
                CreateAuthenticateSessionSetupRequest(TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultUserDomain, TestEnvironmentDefaults.DefaultPassword, challengeResult));

            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected authentication to succeed before session-scoped operations.");
            return successResult.SessionId;
        }

        internal static AuthenticatedTreeContext AuthenticateAndConnectTree(OpenCifsServerHost host)
        {
            ulong sessionId = AuthenticateSession(host);

            OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(
                sessionId,
                new Smb2TreeConnectRequest
                {
                    Path = "\\\\" + TestEnvironmentDefaults.DefaultServerName + "\\" + TestEnvironmentDefaults.DefaultShareName
                });
            TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected tree connect to succeed before file operations.");
            return new AuthenticatedTreeContext(sessionId, treeConnectResult.TreeId);
        }

        internal static AuthenticatedSigningContext AuthenticateSessionAndGetSigningKey(
            OpenCifsServerHost host,
            SmbDialect[]? dialects = null,
            SmbDialect expectedDialect = SmbDialect.Smb2002)
        {
            NegotiateDialect(host, dialects ?? new[] { SmbDialect.Smb2002 }, expectedDialect);

            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest(TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultUserDomain));
            SpnegoNegTokenResp challengeResponseToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResult.Response.SecurityBuffer);
            OpenCifsNtlmChallengeToken challengeToken = OpenCifsNtlmChallengeToken.ReadFrom(challengeResponseToken.ResponseToken!);
            NtlmV2ClientChallenge clientChallenge = new NtlmV2ClientChallenge
            {
                Timestamp = 0x0123456789ABCDEFUL,
                ClientChallenge = Hex("A1A2A3A4A5A6A7A8"),
                AvPairs = new NtlmAvPair[]
                {
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosDomainName,
                        Value = Encoding.Unicode.GetBytes(challengeToken.TargetDomain)
                    },
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosComputerName,
                        Value = Encoding.Unicode.GetBytes(challengeToken.ServerName)
                    }
                },
                TrailingBytes = new byte[4]
            };
            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                password: TestEnvironmentDefaults.DefaultPassword,
                userName: TestEnvironmentDefaults.DefaultUserName,
                userDomain: TestEnvironmentDefaults.DefaultUserDomain,
                serverChallenge: challengeToken.ServerChallenge,
                clientChallenge: clientChallenge);
            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(
                challengeResult.SessionId,
                CreateAuthenticateSessionSetupRequest(TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultUserDomain, TestEnvironmentDefaults.DefaultPassword, challengeResult));
            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected authentication to succeed before signing validation.");
            return new AuthenticatedSigningContext(successResult.SessionId, CreateExpectedSigningKey(responseSet.SessionBaseKey, expectedDialect));
        }

        internal static Smb2NegotiateResponse NegotiateDialect(OpenCifsServerHost host, SmbDialect[] dialects, SmbDialect expectedDialect, Guid? clientGuid = null, Smb2GlobalCapabilities capabilities = Smb2GlobalCapabilities.None)
        {
            Smb2NegotiateResponse negotiateResponse = host.HandleNegotiate(new Smb2NegotiateRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                Capabilities = capabilities,
                ClientGuid = clientGuid ?? Guid.NewGuid(),
                Dialects = dialects
            });
            TestAssertions.Equal(expectedDialect, negotiateResponse.Dialect, "Expected the negotiated dialect to match the requested test precondition.");
            return negotiateResponse;
        }

        internal static byte[] CreateSignedPacketBytes(Smb2Header header, byte[] payload, byte[] signingKey, SmbDialect dialect = SmbDialect.Smb2002)
        {
            Smb2CompoundPacket packet = new Smb2CompoundPacket(
                new List<Smb2CompoundPacketEntry>
                {
                    new Smb2CompoundPacketEntry(header, payload)
                });
            byte[] packetBytes = packet.ToByteArray();

            if ((header.Flags & Smb2HeaderFlags.Signed) == 0)
            {
                return packetBytes;
            }

            IMessageSigner signer = MessageSignerFactory.Create(GetSigningAlgorithmForDialect(dialect));
            Array.Clear(packetBytes, 48, 16);
            byte[] signature = signer.Sign(packetBytes, signingKey, ReadOnlySpan<byte>.Empty);
            Buffer.BlockCopy(signature, 0, packetBytes, 48, signature.Length);
            return packetBytes;
        }

        internal static byte[] CreateExpectedSigningKey(byte[] sessionKey, SmbDialect dialect)
        {
            if (dialect < SmbDialect.Smb30)
            {
                return (byte[])sessionKey.Clone();
            }

            return SmbSessionKeyDerivation.DeriveSigningKey(
                new SmbKeyDerivationInputs
                {
                    SessionKey = (byte[])sessionKey.Clone(),
                    Dialect = dialect,
                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Ccm
                });
        }

        internal static byte[] CreateExpectedSpnegoMechanismListMic(IReadOnlyList<string> mechanismTypes, NtlmNegotiateFlags flags, byte[] sessionKey)
        {
            byte[] mechanismTypeList = EncodeSpnegoMechanismTypeList(mechanismTypes);
            LittleEndianWriter payloadWriter = new LittleEndianWriter();
            payloadWriter.WriteUInt32(0);
            payloadWriter.WriteBytes(mechanismTypeList);
            byte[] checksum = HmacMd5.HashData(
                CreateExpectedNtlmSigningKey(flags, sessionKey, serverToClient: true),
                payloadWriter.ToArray());

            if ((flags & NtlmNegotiateFlags.KeyExchange) != 0)
            {
                checksum = Rc4.Transform(
                    CreateExpectedNtlmSealingKey(flags, sessionKey, serverToClient: true),
                    checksum.AsSpan(0, 8));
            }

            LittleEndianWriter signatureWriter = new LittleEndianWriter();
            signatureWriter.WriteUInt32(1);
            signatureWriter.WriteBytes(checksum.AsSpan(0, 8));
            signatureWriter.WriteUInt32(0);
            return signatureWriter.ToArray();
        }

        internal static byte[] CreateExpectedNtlmSigningKey(NtlmNegotiateFlags flags, byte[] sessionKey, bool serverToClient)
        {
            string direction = serverToClient ? "server-to-client" : "client-to-server";
            byte[] suffix = Encoding.ASCII.GetBytes("session key to " + direction + " signing key magic constant\0");
            byte[] material = new byte[sessionKey.Length + suffix.Length];
            Buffer.BlockCopy(sessionKey, 0, material, 0, sessionKey.Length);
            Buffer.BlockCopy(suffix, 0, material, sessionKey.Length, suffix.Length);
            return MD5.HashData(material);
        }

        internal static byte[] CreateExpectedNtlmSealingKey(NtlmNegotiateFlags flags, byte[] sessionKey, bool serverToClient)
        {
            byte[] baseSealKey;

            if ((flags & NtlmNegotiateFlags.Key128) != 0)
            {
                baseSealKey = (byte[])sessionKey.Clone();
            }
            else if ((flags & NtlmNegotiateFlags.Key56) != 0)
            {
                baseSealKey = sessionKey[..Math.Min(7, sessionKey.Length)];
            }
            else
            {
                baseSealKey = sessionKey[..Math.Min(5, sessionKey.Length)];
            }

            string direction = serverToClient ? "server-to-client" : "client-to-server";
            byte[] suffix = Encoding.ASCII.GetBytes("session key to " + direction + " sealing key magic constant\0");
            byte[] material = new byte[baseSealKey.Length + suffix.Length];
            Buffer.BlockCopy(baseSealKey, 0, material, 0, baseSealKey.Length);
            Buffer.BlockCopy(suffix, 0, material, baseSealKey.Length, suffix.Length);
            return MD5.HashData(material);
        }

        internal static byte[] EncodeSpnegoMechanismTypeList(IReadOnlyList<string> mechanismTypes)
        {
            AsnWriter writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();

            for (int index = 0; index < mechanismTypes.Count; index++)
            {
                writer.WriteObjectIdentifier(mechanismTypes[index]);
            }

            writer.PopSequence();
            return writer.Encode();
        }

        internal static byte[] ExtractSessionBaseKey(string userName, string userDomain, string password, OpenCifsServerSessionSetupResult challengeResult)
        {
            SpnegoNegTokenResp challengeToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResult.Response.SecurityBuffer);
            NtlmChallengeMessage challengeMessage = NtlmChallengeMessage.ReadFrom(challengeToken.ResponseToken!);
            NtlmV2ClientChallenge clientChallenge = new NtlmV2ClientChallenge
            {
                Timestamp = TryGetChallengeTimestamp(challengeMessage.TargetInfo, out ulong timestamp)
                    ? timestamp
                    : 0,
                ClientChallenge = Hex("A1A2A3A4A5A6A7A8"),
                AvPairs = CloneAvPairs(challengeMessage.TargetInfo),
                TrailingBytes = new byte[4]
            };

            return NtlmV2Authentication.CreateChallengeResponseSet(
                password: password,
                userName: userName,
                userDomain: userDomain,
                serverChallenge: challengeMessage.ServerChallenge,
                clientChallenge: clientChallenge).SessionBaseKey;
        }

        internal static SigningAlgorithmId GetSigningAlgorithmForDialect(SmbDialect dialect)
        {
            switch (dialect)
            {
                case SmbDialect.Smb30:
                case SmbDialect.Smb302:
                    return SigningAlgorithmId.AesCmac;
                default:
                    return SigningAlgorithmId.HmacSha256;
            }
        }

        internal static Smb2CreateRequest CreateFileCreateRequest(
            string path,
            Smb2CreateDisposition disposition,
            uint desiredAccess = 0xC0000000U,
            uint shareAccess = 0x00000007U,
            Smb2CreateOptions createOptions = Smb2CreateOptions.NonDirectoryFile,
            OpenCIFS.Protocol.FileAttributes fileAttributes = OpenCIFS.Protocol.FileAttributes.Normal)
        {
            Smb2CreateRequest request = new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.None,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = desiredAccess,
                FileAttributes = fileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = disposition,
                CreateOptions = createOptions,
                Name = path,
                CreateContexts = Array.Empty<byte>()
            };

            Smb2CreateRequestValidator.Validate(request);
            return request;
        }

        internal static Smb2SessionSetupRequest CreateInitialSessionSetupRequest(string userName, string userDomain)
        {
            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenInit(new SpnegoNegTokenInit
                {
                    MechanismTypes = new string[] { SpnegoMechanismOid.Ntlm },
                    MechanismToken = new OpenCifsNtlmNegotiateToken
                    {
                        UserName = userName,
                        UserDomain = userDomain
                    }.ToByteArray()
                })
            };

            Smb2SessionSetupRequestValidator.Validate(request);
            return request;
        }

        internal static Smb2SessionSetupRequest CreateStandardInitialSessionSetupRequest(string userName, string userDomain)
        {
            NtlmNegotiateMessage negotiateMessage = new NtlmNegotiateMessage
            {
                Flags =
                    NtlmNegotiateFlags.Unicode |
                    NtlmNegotiateFlags.RequestTarget |
                    NtlmNegotiateFlags.Sign |
                    NtlmNegotiateFlags.Seal |
                    NtlmNegotiateFlags.AlwaysSign |
                    NtlmNegotiateFlags.Ntlm |
                    NtlmNegotiateFlags.ExtendedSessionSecurity |
                    NtlmNegotiateFlags.Key128 |
                    NtlmNegotiateFlags.Key56,
                DomainName = userDomain,
                Workstation = string.Empty
            };

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenInit(new SpnegoNegTokenInit
                {
                    MechanismTypes = new string[] { SpnegoMechanismOid.Ntlm },
                    MechanismToken = negotiateMessage.ToByteArray()
                })
            };

            Smb2SessionSetupRequestValidator.Validate(request);
            return request;
        }

        internal static Smb2SessionSetupRequest CreateAuthenticateSessionSetupRequest(string userName, string userDomain, string password, OpenCifsServerSessionSetupResult challengeResult)
        {
            SpnegoNegTokenResp challengeResponseToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResult.Response.SecurityBuffer);
            OpenCifsNtlmChallengeToken challengeToken = OpenCifsNtlmChallengeToken.ReadFrom(challengeResponseToken.ResponseToken!);

            NtlmV2ClientChallenge clientChallenge = new NtlmV2ClientChallenge
            {
                Timestamp = 0x0123456789ABCDEFUL,
                ClientChallenge = Hex("A1A2A3A4A5A6A7A8"),
                AvPairs = new NtlmAvPair[]
                {
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosDomainName,
                        Value = System.Text.Encoding.Unicode.GetBytes(challengeToken.TargetDomain)
                    },
                    new NtlmAvPair
                    {
                        AvId = NtlmAvPairId.NetBiosComputerName,
                        Value = System.Text.Encoding.Unicode.GetBytes(challengeToken.ServerName)
                    }
                },
                TrailingBytes = new byte[4]
            };

            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                password: password,
                userName: userName,
                userDomain: userDomain,
                serverChallenge: challengeToken.ServerChallenge,
                clientChallenge: clientChallenge);

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    ResponseToken = new OpenCifsNtlmAuthenticateToken
                    {
                        UserName = userName,
                        UserDomain = userDomain,
                        NtChallengeResponse = responseSet.NtChallengeResponse.ToByteArray(),
                        LmChallengeResponse = responseSet.LmChallengeResponse
                    }.ToByteArray()
                })
            };

            Smb2SessionSetupRequestValidator.Validate(request);
            return request;
        }

        internal static Smb2SessionSetupRequest CreateStandardAuthenticateSessionSetupRequest(string userName, string userDomain, string password, OpenCifsServerSessionSetupResult challengeResult)
        {
            NtlmNegotiateMessage negotiateMessage = new NtlmNegotiateMessage
            {
                Flags =
                    NtlmNegotiateFlags.Unicode |
                    NtlmNegotiateFlags.RequestTarget |
                    NtlmNegotiateFlags.Sign |
                    NtlmNegotiateFlags.Seal |
                    NtlmNegotiateFlags.AlwaysSign |
                    NtlmNegotiateFlags.Ntlm |
                    NtlmNegotiateFlags.ExtendedSessionSecurity |
                    NtlmNegotiateFlags.Key128 |
                    NtlmNegotiateFlags.Key56,
                DomainName = userDomain,
                Workstation = string.Empty
            };

            SpnegoNegTokenResp challengeToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResult.Response.SecurityBuffer);
            NtlmChallengeMessage challengeMessage = NtlmChallengeMessage.ReadFrom(challengeToken.ResponseToken!);
            NtlmV2ClientChallenge clientChallenge = new NtlmV2ClientChallenge
            {
                Timestamp = TryGetChallengeTimestamp(challengeMessage.TargetInfo, out ulong timestamp)
                    ? timestamp
                    : DeterministicTestClock.GetFileTimeUtc("ServerTestSuites.CreateStandardAuthenticateSessionSetupRequest"),
                ClientChallenge = Hex("A1A2A3A4A5A6A7A8"),
                AvPairs = CloneAvPairs(challengeMessage.TargetInfo),
                TrailingBytes = new byte[4]
            };
            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                password: password,
                userName: userName,
                userDomain: userDomain,
                serverChallenge: challengeMessage.ServerChallenge,
                clientChallenge: clientChallenge);
            NtlmAuthenticateMessage authenticateMessage = new NtlmAuthenticateMessage
            {
                Flags = challengeMessage.Flags & (
                    NtlmNegotiateFlags.Unicode |
                    NtlmNegotiateFlags.Sign |
                    NtlmNegotiateFlags.Seal |
                    NtlmNegotiateFlags.Ntlm |
                    NtlmNegotiateFlags.AlwaysSign |
                    NtlmNegotiateFlags.ExtendedSessionSecurity |
                    NtlmNegotiateFlags.Key128 |
                    NtlmNegotiateFlags.Key56),
                LmChallengeResponse = responseSet.LmChallengeResponse,
                NtChallengeResponse = responseSet.NtChallengeResponse.ToByteArray(),
                DomainName = userDomain,
                UserName = userName,
                Workstation = string.Empty,
                IncludeMessageIntegrityCodeField = true
            };
            byte[] negotiateBytes = negotiateMessage.ToByteArray();
            byte[] challengeBytes = challengeToken.ResponseToken!;
            byte[] authenticateBytesWithZeroMic = authenticateMessage.ToByteArray(zeroMessageIntegrityCode: true);
            authenticateMessage.MessageIntegrityCode = NtlmMessageIntegrityCode.Compute(
                exportedSessionKey: responseSet.SessionBaseKey,
                negotiateMessage: negotiateBytes,
                challengeMessage: challengeBytes,
                authenticateMessageWithZeroMic: authenticateBytesWithZeroMic);

            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    ResponseToken = authenticateMessage.ToByteArray()
                })
            };

            Smb2SessionSetupRequestValidator.Validate(request);
            return request;
        }

        internal static NtlmAvPair[] CloneAvPairs(IReadOnlyList<NtlmAvPair> avPairs)
        {
            NtlmAvPair[] clonedPairs = new NtlmAvPair[avPairs.Count];

            for (int index = 0; index < avPairs.Count; index++)
            {
                clonedPairs[index] = new NtlmAvPair
                {
                    AvId = avPairs[index].AvId,
                    Value = (byte[])avPairs[index].Value.Clone()
                };
            }

            return clonedPairs;
        }

        internal static bool TryGetChallengeTimestamp(IReadOnlyList<NtlmAvPair> avPairs, out ulong timestamp)
        {
            for (int index = 0; index < avPairs.Count; index++)
            {
                if (avPairs[index].AvId != NtlmAvPairId.Timestamp || avPairs[index].Value.Length != 8)
                {
                    continue;
                }

                timestamp = new LittleEndianReader(avPairs[index].Value).ReadUInt64();
                return true;
            }

            timestamp = 0;
            return false;
        }

        internal static Smb2Header CreateRequestHeader(Smb2Command command, ulong messageId, ushort creditRequest = 1, ushort creditCharge = 0, Smb2HeaderFlags flags = Smb2HeaderFlags.None, ulong sessionId = 0, uint treeId = 0, ulong asyncId = 0)
        {
            return new Smb2Header
            {
                CreditCharge = creditCharge,
                Status = NtStatus.Success,
                Command = command,
                CreditRequest = creditRequest,
                Flags = flags,
                NextCommand = 0,
                MessageId = messageId,
                TreeId = (flags & Smb2HeaderFlags.AsyncCommand) == 0 ? treeId : 0,
                AsyncId = asyncId,
                SessionId = sessionId,
                Signature = new byte[16]
            };
        }

        internal static IReadOnlyList<DirectTcpMutationRequestBaseline> BuildDirectTcpMutationRequestBaselines()
        {
            Smb2NegotiateRequest smb2NegotiateRequest = new Smb2NegotiateRequest
            {
                ClientGuid = Guid.Parse("3E10F3B9-6D5C-4F5D-8C65-F53433093A8A"),
                SecurityMode = Smb2SecurityMode.SigningEnabled,
                Capabilities = Smb2GlobalCapabilities.None,
                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
            };

            Smb2CompoundPacket smb2Packet = new Smb2CompoundPacket(new[]
            {
                new Smb2CompoundPacketEntry(
                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2),
                    smb2NegotiateRequest.ToByteArray())
            });

            Smb1NegotiateRequest smb1Request = new Smb1NegotiateRequest
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

            return new List<DirectTcpMutationRequestBaseline>
            {
                new DirectTcpMutationRequestBaseline("Smb2NegotiatePacket", smb2Packet.ToByteArray()),
                new DirectTcpMutationRequestBaseline("Smb1MultiProtocolNegotiate", smb1Request.ToByteArray())
            };
        }

        internal static byte[] Hex(string value)
        {
            return Convert.FromHexString(value.Replace(" ", string.Empty));
        }

        internal static int AllocateTcpPort()
        {
            return ServerDirectTcpTestSupport.AllocateTcpPort();
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(int port, CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.StartDirectTcpServerAsync(port, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            int port,
            bool requireEncryptionForSmb3,
            CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.StartDirectTcpServerAsync(
                port,
                requireEncryptionForSmb3,
                cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            int port,
            Action<Exception> exceptionHandler,
            CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.StartDirectTcpServerAsync(
                port,
                exceptionHandler,
                cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            int port,
            bool requireEncryptionForSmb3,
            Action<Exception> exceptionHandler,
            CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.StartDirectTcpServerAsync(
                port,
                requireEncryptionForSmb3,
                exceptionHandler,
                cancellationToken).ConfigureAwait(false);
        }

        internal static async Task StopDirectTcpServerAsync(CancellationTokenSource serverCancellationTokenSource, Task serverTask)
        {
            await ServerDirectTcpTestSupport.StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
        }

        internal static void ReleaseDirectTcpPortReservation()
        {
            ServerDirectTcpTestSupport.ReleaseDirectTcpPortReservation();
        }

        internal static async Task WriteDirectTcpFrameAsync(NetworkStream stream, byte[] payload, CancellationToken cancellationToken)
        {
            await ServerDirectTcpTestSupport.WriteDirectTcpFrameAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<byte[]> ReadDirectTcpFramePayloadAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.ReadDirectTcpFramePayloadAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<byte[]?> TryReadDirectTcpFramePayloadAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.TryReadDirectTcpFramePayloadAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task AssertNegotiatesDirectTcpRequestAsync(int port, byte[] requestPayload, CancellationToken cancellationToken)
        {
            await ServerDirectTcpTestSupport.AssertNegotiatesDirectTcpRequestAsync(port, requestPayload, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<byte[]?> SendMalformedDirectTcpFrameAsync(int port, byte[] requestPayload, CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.SendMalformedDirectTcpFrameAsync(port, requestPayload, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task<int> ReadExactOrDetectCloseAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            return await ServerDirectTcpTestSupport.ReadExactOrDetectCloseAsync(stream, buffer, cancellationToken).ConfigureAwait(false);
        }

        internal static async Task WaitForTcpListenerStateAsync(int port, bool shouldAcceptConnections, CancellationToken cancellationToken)
        {
            await ServerDirectTcpTestSupport.WaitForTcpListenerStateAsync(port, shouldAcceptConnections, cancellationToken).ConfigureAwait(false);
        }

        internal static void DeleteDirectoryForcefully(string rootPath)
        {
            TestPathUtilities.DeleteDirectoryForcefully(rootPath);
        }

        internal static SampleProgramExecutionResult RunSampleProgram(params string[] args)
        {
            return ServerSampleProgramTestSupport.RunSampleProgram(args);
        }
    }
}
