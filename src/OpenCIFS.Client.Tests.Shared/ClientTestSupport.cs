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
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal static class ClientTestSupport
    {
        private const string DirectTcpPortReservationSemaphoreName = "OpenCIFS.DirectTcpTestPortReservation";
        private static readonly AsyncLocal<DirectTcpPortReservation?> _CurrentDirectTcpPortReservation = new AsyncLocal<DirectTcpPortReservation?>();
        internal static OpenCifsClientSession CreateNegotiatedClient(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsClientSession session = new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER",
                PreferEncryption = dialect < SmbDialect.Smb30
            });
            session.CreateNegotiateRequest();
            Smb2GlobalCapabilities capabilities = Smb2GlobalCapabilities.None;

            if (dialect >= SmbDialect.Smb21)
            {
                capabilities |= Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing;
            }

            if (dialect >= SmbDialect.Smb30)
            {
                capabilities |= Smb2GlobalCapabilities.Encryption;
            }

            session.ApplyNegotiateResponse(new Smb2NegotiateResponse
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                Dialect = dialect,
                ServerGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f"),
                MaxTransactSize = 65536,
                MaxReadSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect),
                MaxWriteSize = Smb2CreditChargeHelper.GetImplementedReadWriteSize(dialect),
                Capabilities = capabilities
            });
            return session;
        }

        internal static OpenCifsClientSession CreateAuthenticatedClient(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsClientSession session = CreateNegotiatedClient(dialect);
            OpenCifsClientCredential credential = CreateCredential();
            session.CreateSessionSetupRequest(credential);
            session.CreateSessionAuthenticateRequest(
                credential,
                sessionId: 9,
                status: NtStatus.MoreProcessingRequired,
                challengeResponse: CreateChallengeResponse("LAB-SERVER", "WORKGROUP", Hex("0123456789ABCDEF")));
            session.ApplySessionSetupResult(9, NtStatus.Success, CreateSessionSetupSuccessResponse());
            return session;
        }

        internal static OpenCifsClientSession CreateAuthenticatedTreeClient()
        {
            OpenCifsClientSession session = CreateAuthenticatedClient();
            session.ApplyTreeConnectResult("public", 42, NtStatus.Success, CreateTreeConnectSuccessResponse());
            return session;
        }

        internal static AuthenticatedLoopbackPair CreateAuthenticatedLoopbackPair(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsServerHost host = CreateLoopbackServerHost(dialect);
            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
            {
                ServerName = "LAB-SERVER",
                MaximumDialect = dialect,
                PreferEncryption = dialect < SmbDialect.Smb30
            });
            OpenCifsClientCredential credential = CreateCredential();
            Smb2NegotiateResponse negotiateResponse = host.HandleNegotiate(client.CreateNegotiateRequest());
            client.ApplyNegotiateResponse(negotiateResponse);

            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, client.CreateSessionSetupRequest(credential));
            Smb2SessionSetupRequest authenticateRequest = client.CreateSessionAuthenticateRequest(
                credential,
                challengeResult.SessionId,
                challengeResult.Status,
                challengeResult.Response);
            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);
            client.ApplySessionSetupResult(successResult.SessionId, successResult.Status, successResult.Response);
            return new AuthenticatedLoopbackPair(host, client, successResult.SessionId);
        }

        internal static OpenCifsServerHost CreateLoopbackServerHost(SmbDialect dialect = SmbDialect.Smb2002)
        {
            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
            {
                ServerName = TestEnvironmentDefaults.DefaultServerName,
                MaximumDialect = dialect,
                RequireEncryptionForSmb3 = dialect < SmbDialect.Smb30
            });
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = "SampleShare",
                CreateRootIfMissing = true
            });
            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });
            return builder.BuildHost();
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

        internal static Smb2SessionSetupResponse CreateChallengeResponse(string serverName, string userDomain, byte[] serverChallenge)
        {
            LittleEndianWriter timestampWriter = new LittleEndianWriter();
            timestampWriter.WriteUInt64(DeterministicTestClock.GetFileTimeUtc("ClientTestSuites.CreateChallengeResponse"));

            return new Smb2SessionSetupResponse
            {
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptIncomplete,
                    SupportedMechanism = SpnegoMechanismOid.Ntlm,
                    ResponseToken = new NtlmChallengeMessage
                    {
                        Flags =
                            NtlmNegotiateFlags.Unicode |
                            NtlmNegotiateFlags.RequestTarget |
                            NtlmNegotiateFlags.Sign |
                            NtlmNegotiateFlags.Seal |
                            NtlmNegotiateFlags.AlwaysSign |
                            NtlmNegotiateFlags.Ntlm |
                            NtlmNegotiateFlags.ExtendedSessionSecurity |
                            NtlmNegotiateFlags.TargetInfo |
                            NtlmNegotiateFlags.TargetTypeServer |
                            NtlmNegotiateFlags.Key128 |
                            NtlmNegotiateFlags.Key56,
                        ServerChallenge = serverChallenge,
                        TargetName = serverName,
                        TargetInfo = new NtlmAvPair[]
                        {
                            new NtlmAvPair
                            {
                                AvId = NtlmAvPairId.NetBiosComputerName,
                                Value = System.Text.Encoding.Unicode.GetBytes(serverName)
                            },
                            new NtlmAvPair
                            {
                                AvId = NtlmAvPairId.NetBiosDomainName,
                                Value = System.Text.Encoding.Unicode.GetBytes(userDomain)
                            },
                            new NtlmAvPair
                            {
                                AvId = NtlmAvPairId.Timestamp,
                                Value = timestampWriter.ToArray()
                            }
                        }
                    }.ToByteArray()
                })
            };
        }

        internal static Smb2SessionSetupResponse CreateSessionSetupSuccessResponse(Smb2SessionFlags sessionFlags = Smb2SessionFlags.None)
        {
            return new Smb2SessionSetupResponse
            {
                SessionFlags = sessionFlags,
                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                {
                    NegotiationState = SpnegoNegState.AcceptCompleted,
                    SupportedMechanism = SpnegoMechanismOid.Ntlm
                })
            };
        }

        internal static Smb2TreeConnectResponse CreateTreeConnectSuccessResponse()
        {
            return new Smb2TreeConnectResponse
            {
                ShareType = Smb2ShareType.Disk,
                ShareFlags = 0,
                Capabilities = 0,
                MaximalAccess = 0x001F01FF
            };
        }

        internal static Smb2Header CreateResponseHeader(Smb2Header requestHeader, ushort grantedCredits = 1, NtStatus status = NtStatus.Success, Smb2HeaderFlags flags = Smb2HeaderFlags.ServerToRedir, ushort creditCharge = 0, ulong asyncId = 0)
        {
            return new Smb2Header
            {
                CreditCharge = creditCharge,
                Status = status,
                Command = requestHeader.Command,
                CreditRequest = grantedCredits,
                Flags = flags,
                NextCommand = 0,
                MessageId = requestHeader.MessageId,
                TreeId = (flags & Smb2HeaderFlags.AsyncCommand) == 0 ? requestHeader.TreeId : 0,
                AsyncId = asyncId,
                SessionId = requestHeader.SessionId,
                Signature = new byte[16]
            };
        }

        internal static void GrantCredits(OpenCifsClientSession session, ushort creditCount)
        {
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Negotiate, creditRequest: creditCount);
            session.ApplyResponseHeader(CreateResponseHeader(requestHeader, grantedCredits: creditCount));
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
                bytes[index] = unchecked((byte)('A' + (index % 23)));
            }

            return bytes;
        }

        internal static async Task<DirectTcpServerHandle> StartDirectTcpServerAsync(
            string sharePath,
            int port,
            CancellationToken cancellationToken,
            int maximumCredits = 64,
            SmbDialect? minimumDialect = null,
            SmbDialect? maximumDialect = null,
            bool? requireEncryptionForSmb3 = null,
            bool enableShareBrowsing = false,
            bool enableUtf8EchoPipe = false,
            OpenCifsServerDfsReferral? dfsReferral = null,
            IReadOnlyCollection<OpenCifsServerDfsReferral>? dfsReferrals = null,
            bool enableSmb311Preview = false,
            IReadOnlyCollection<OpenCifsServerFileSystemShare>? additionalShares = null)
        {
            DirectTcpPortReservation reservation = GetDirectTcpPortReservation(port);
            OpenCifsServerOptions options = new OpenCifsServerOptions
            {
                ServerName = "127.0.0.1",
                BindAddress = "127.0.0.1",
                BindPort = port,
                MaximumCredits = maximumCredits
            };

            if (minimumDialect.HasValue)
            {
                options.MinimumDialect = minimumDialect.Value;
            }

            if (maximumDialect.HasValue)
            {
                options.MaximumDialect = maximumDialect.Value;
            }

            if (requireEncryptionForSmb3.HasValue)
            {
                options.RequireEncryptionForSmb3 = requireEncryptionForSmb3.Value;
            }

            options.EnableSmb311Preview = enableSmb311Preview;

            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(options);
            builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
            {
                ShareName = TestEnvironmentDefaults.DefaultShareName,
                RootPath = sharePath,
                CreateRootIfMissing = true
            });

            if (additionalShares != null)
            {
                foreach (OpenCifsServerFileSystemShare additionalShare in additionalShares)
                {
                    builder.AddFileSystemShare(additionalShare);
                }
            }

            builder.AddAccount(new OpenCifsServerAccount
            {
                UserName = TestEnvironmentDefaults.DefaultUserName,
                UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                Password = TestEnvironmentDefaults.DefaultPassword
            });

            if (enableShareBrowsing)
            {
                builder.AddSrvsvcShareEnumerationEndpoint();
            }

            if (enableUtf8EchoPipe)
            {
                builder.AddUtf8EchoNamedPipeEndpoint();
            }

            if (dfsReferral != null)
            {
                builder.AddDfsReferral(dfsReferral);
            }

            if (dfsReferrals != null)
            {
                foreach (OpenCifsServerDfsReferral configuredReferral in dfsReferrals)
                {
                    builder.AddDfsReferral(configuredReferral);
                }
            }

            OpenCifsDirectTcpServer server = builder.BuildDirectTcpServer();
            CancellationTokenSource serverCancellationTokenSource = new CancellationTokenSource();
            Task serverTask = server.RunAsync(serverCancellationTokenSource.Token);

            try
            {
                await WaitForDirectTcpServerAsync(reservation.Port, cancellationToken).ConfigureAwait(false);
                return new DirectTcpServerHandle(serverCancellationTokenSource, serverTask);
            }
            catch
            {
                serverCancellationTokenSource.Cancel();

                try
                {
                    await serverTask.ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                }
                finally
                {
                    serverCancellationTokenSource.Dispose();
                    ReleaseDirectTcpPortReservation();
                }

                throw;
            }
        }

        internal static async Task StopDirectTcpServerAsync(CancellationTokenSource serverCancellationTokenSource, Task serverTask)
        {
            serverCancellationTokenSource.Cancel();

            try
            {
                await serverTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            finally
            {
                serverCancellationTokenSource.Dispose();
                ReleaseDirectTcpPortReservation();
            }
        }

        internal static async Task WaitForDirectTcpServerAsync(int port, CancellationToken cancellationToken)
        {
            for (int attempt = 0; attempt < 40; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                using TcpClient tcpClient = new TcpClient();

                try
                {
                    using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(250);
                    using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);
                    await tcpClient.ConnectAsync(IPAddress.Loopback, port, linkedTokenSource.Token).ConfigureAwait(false);
                    return;
                }
                catch (SocketException)
                {
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                }

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }

            throw new InvalidOperationException("Timed out waiting for the direct-TCP test server to accept connections.");
        }

        internal static int AllocateTcpPort()
        {
            if (_CurrentDirectTcpPortReservation.Value != null)
            {
                throw new InvalidOperationException("A direct-TCP test port is already reserved on this async flow.");
            }

            Semaphore? semaphore = new Semaphore(initialCount: 1, maximumCount: 1, name: DirectTcpPortReservationSemaphoreName);
            bool lockTaken = false;

            try
            {
                lockTaken = semaphore.WaitOne(TimeSpan.FromSeconds(30));

                if (!lockTaken)
                {
                    throw new InvalidOperationException("Timed out waiting to reserve the shared direct-TCP test port allocator.");
                }

                TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();

                try
                {
                    int port = ((IPEndPoint)listener.LocalEndpoint).Port;
                    _CurrentDirectTcpPortReservation.Value = new DirectTcpPortReservation(semaphore, port);
                    semaphore = null;
                    return port;
                }
                finally
                {
                    listener.Stop();
                }
            }
            catch
            {
                if (semaphore != null)
                {
                    if (lockTaken)
                    {
                        semaphore.Release();
                    }

                    semaphore.Dispose();
                }

                throw;
            }
        }

        private static DirectTcpPortReservation GetDirectTcpPortReservation(int port)
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;

            if (reservation == null || reservation.Port != port)
            {
                throw new InvalidOperationException("Expected a reserved direct-TCP test port before starting the server.");
            }

            return reservation;
        }

        internal static void ReleaseDirectTcpPortReservation()
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;
            _CurrentDirectTcpPortReservation.Value = null;

            if (reservation == null)
            {
                return;
            }

            reservation.Semaphore.Release();
            reservation.Semaphore.Dispose();
        }

        private sealed class DirectTcpPortReservation
        {
            public DirectTcpPortReservation(Semaphore semaphore, int port)
            {
                Semaphore = semaphore ?? throw new ArgumentNullException(nameof(semaphore));
                Port = port;
            }

            public Semaphore Semaphore { get; }

            public int Port { get; }
        }

        internal static byte[] Hex(string value)
        {
            return Convert.FromHexString(value.Replace(" ", string.Empty));
        }
    }
}
