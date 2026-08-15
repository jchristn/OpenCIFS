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
    internal static class ServerNegotiationBaselineCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "AdvertisedDialectsOnlyIncludeImplementedValues",
                        displayName: "Server advertise list is clamped to the implemented SMB 2.0.2 through SMB 3.0.2 dialects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions());
                            SmbDialect[] advertisedDialects = host.GetAdvertisedDialects();

                            if (advertisedDialects.Length != 4)
                            {
                                throw new InvalidOperationException("Expected exactly four currently implemented server dialects.");
                            }

                            if (advertisedDialects[0] != SmbDialect.Smb2002 ||
                                advertisedDialects[1] != SmbDialect.Smb21 ||
                                advertisedDialects[2] != SmbDialect.Smb30 ||
                                advertisedDialects[3] != SmbDialect.Smb302)
                            {
                                throw new InvalidOperationException("Expected SMB 2.0.2, SMB 2.1, SMB 3.0, and SMB 3.0.2 to be the currently implemented server dialects.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerNegotiatesSmb21WithSigningRequired",
                        displayName: "Server negotiate handling selects SMB 2.1 and enforces signing policy",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions());
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };

                            Smb2NegotiateResponse response = host.HandleNegotiate(request);

                            if (response.Dialect != SmbDialect.Smb21)
                            {
                                throw new InvalidOperationException("Expected the server to negotiate SMB 2.1.");
                            }

                            if ((response.SecurityMode & Smb2SecurityMode.SigningRequired) == 0)
                            {
                                throw new InvalidOperationException("Expected the server to require signing by default.");
                            }

                            if (response.ServerGuid != host.ServerGuid)
                            {
                                throw new InvalidOperationException("Expected the negotiated server GUID to match the host GUID.");
                            }

                            if ((response.Capabilities & Smb2GlobalCapabilities.LargeMtu) == 0)
                            {
                                throw new InvalidOperationException("Expected the SMB 2.1 negotiate response to advertise SMB2_GLOBAL_CAP_LARGE_MTU for the bounded multi-credit slice.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerRejectsRequestsWithoutCommonDialect",
                        displayName: "Server negotiate handling rejects requests that do not share a common dialect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions());
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new SmbDialect[] { SmbDialect.Smb311 }
                            };

                            try
                            {
                                host.HandleNegotiate(request);
                            }
                            catch (OpenCifsServerStateException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected negotiate handling to reject a request without a common implemented dialect.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerClampsAdvertisedDialectsToConfiguredMaximum",
                        displayName: "Server advertise list clamps to a configured SMB 2.0.2 maximum",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            SmbDialect[] advertisedDialects = host.GetAdvertisedDialects();

                            TestAssertions.Equal(1, advertisedDialects.Length, "Expected the server dialect list to clamp to SMB 2.0.2.");
                            TestAssertions.Equal(SmbDialect.Smb2002, advertisedDialects[0], "Expected the configured maximum dialect to clamp server negotiate advertisement.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerAdvertisesOptInSmb302DialectsWhenEncryptionIsNotRequired",
                        displayName: "Server advertises SMB 3.0 and SMB 3.0.2 by default even when SMB 3.x encryption is required",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions());
                            SmbDialect[] advertisedDialects = host.GetAdvertisedDialects();

                            TestAssertions.Equal(4, advertisedDialects.Length, "Expected the default server dialect list to include SMB 3.0 and SMB 3.0.2.");
                            TestAssertions.Equal(SmbDialect.Smb2002, advertisedDialects[0], "Unexpected first default server dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, advertisedDialects[1], "Unexpected second default server dialect.");
                            TestAssertions.Equal(SmbDialect.Smb30, advertisedDialects[2], "Unexpected third default server dialect.");
                            TestAssertions.Equal(SmbDialect.Smb302, advertisedDialects[3], "Unexpected fourth default server dialect.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerNegotiatesOptInSmb302WithBoundedCapabilities",
                        displayName: "Server negotiate handling selects SMB 3.0.2 with bounded encryption capability when the client advertises it",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                RequireEncryptionForSmb3 = false
                            });
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302 }
                            };

                            Smb2NegotiateResponse response = host.HandleNegotiate(request);

                            TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the opted-in server to negotiate SMB 3.0.2.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                response.Capabilities,
                                "Expected the SMB 3.0.2 response to advertise the implemented large-MTU, leasing, and encryption capabilities.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerClampsRequiredEncryptionSmb3NegotiationToSmb21WhenClientOmitsEncryptionCapability",
                        displayName: "Server clamps required-encryption SMB3 negotiation to SMB 2.1 when the client omits encryption capability",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions());
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302 }
                            };

                            Smb2NegotiateResponse response = host.HandleNegotiate(request);

                            TestAssertions.Equal(SmbDialect.Smb21, response.Dialect, "Expected the server to clamp to SMB 2.1 when SMB3 encryption is required but not advertised by the client.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerPreservesPinnedSmb302RangeWhenRequiredEncryptionHasNoSmb21Fallback",
                        displayName: "Server preserves a pinned SMB 3.0.2 range when required-encryption negotiation has no SMB 2.1 fallback",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true
                            });
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb302 }
                            };

                            Smb2NegotiateResponse response = host.HandleNegotiate(request);

                            TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the required-encryption dialect clamp to preserve the configured SMB 3.0.2-only range.");
                            return Task.CompletedTask;
                        }),
            };
        }
    }
}

