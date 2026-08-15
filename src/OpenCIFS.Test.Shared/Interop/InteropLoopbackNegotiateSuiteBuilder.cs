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
    internal static class InteropLoopbackNegotiateSuiteBuilder
    {
        /// <summary>
        /// Build the loopback negotiate suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor LoopbackNegotiateSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.Loopback",
                displayName: "Loopback negotiate coverage",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerNegotiateDefaultSmb302",
                        displayName: "Client and server loopback negotiate default SMB 3.0.2 with matching GUID, signing state, and encryption capability",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions());
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions());
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            if (client.NegotiatedDialect != SmbDialect.Smb302)
                            {
                                throw new InvalidOperationException("Expected loopback negotiation to select SMB 3.0.2 by default.");
                            }

                            if (client.ServerGuid != server.ServerGuid)
                            {
                                throw new InvalidOperationException("Expected the client to observe the server host GUID.");
                            }

                            if (!client.IsSigningRequired)
                            {
                                throw new InvalidOperationException("Expected loopback negotiation to require signing by default.");
                            }

                            if ((response.Capabilities & Smb2GlobalCapabilities.Encryption) == 0)
                            {
                                throw new InvalidOperationException("Expected the default loopback negotiate response to advertise bounded SMB3 encryption capability.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerSmb311PreviewNegotiateSmb311DialectWithTypedContextsWhenBothOptIn",
                        displayName: "Client and server loopback SMB 3.1.1 preview negotiate the SMB 3.1.1 dialect with typed Preauth and Encryption response contexts when both sides opt in",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                EnableSmb311Preview = true,
                                PreferEncryption = false
                            });
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            TestAssertions.True(Array.IndexOf(request.Dialects, SmbDialect.Smb311) >= 0, "Expected the SMB 3.1.1 preview client to advertise the SMB 3.1.1 dialect.");
                            TestAssertions.Equal((ushort)4, request.NegotiateContextCount, "Expected the SMB 3.1.1 preview client to advertise four typed negotiate-context entries.");

                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            TestAssertions.Equal(SmbDialect.Smb311, response.Dialect, "Expected the loopback server to negotiate the SMB 3.1.1 dialect when both sides opt in.");
                            TestAssertions.True(response.NegotiateContextCount >= 1, "Expected the SMB 3.1.1 preview server to emit at least one typed response negotiate-context entry.");

                            client.ApplyNegotiateResponse(response);
                            TestAssertions.Equal(SmbDialect.Smb311, client.NegotiatedDialect!.Value, "Expected the SMB 3.1.1 preview client to track the negotiated SMB 3.1.1 dialect.");

                            byte[]? clientHash = client.GetCurrentPreauthIntegrityHash();
                            byte[]? serverHash = server.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(clientHash != null && serverHash != null, "Expected both sides of the loopback SMB 3.1.1 preview slice to allocate a preauth integrity hash accumulator.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerRespectOptionalSigningPolicy",
                        displayName: "Client and server loopback negotiate default SMB 3.0.2 while keeping signing optional when both sides relax the policy",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                RequireSigning = false
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                RequireSigning = false
                            });
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            if (client.NegotiatedDialect != SmbDialect.Smb302)
                            {
                                throw new InvalidOperationException("Expected loopback negotiation to keep SMB 3.0.2 selected.");
                            }

                            if (client.IsSigningRequired)
                            {
                                throw new InvalidOperationException("Expected signing to stay optional when both sides relax the policy.");
                            }

                            if ((response.SecurityMode & Smb2SecurityMode.SigningEnabled) == 0)
                            {
                                throw new InvalidOperationException("Expected signing to remain enabled even when it is not required.");
                            }

                            if ((response.Capabilities & Smb2GlobalCapabilities.Encryption) == 0)
                            {
                                throw new InvalidOperationException("Expected the relaxed-signing loopback negotiate response to continue advertising bounded SMB3 encryption capability.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerRejectNegotiationWithoutCommonDialect",
                        displayName: "Client and server loopback reject negotiation when there is no common dialect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb21,
                                MaximumDialect = SmbDialect.Smb21
                            });
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => server.HandleNegotiate(request),
                                "Expected loopback negotiate coverage to reject client/server dialect ranges without a common SMB2 dialect.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerClampNegotiationToSmb2002WhenConfigured",
                        displayName: "Client and server loopback clamp negotiation to SMB 2.0.2 when both sides cap the dialect range",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            OpenCifsClientSession client = new OpenCifsClientSession(new OpenCifsClientOptions
                            {
                                MinimumDialect = SmbDialect.Smb2002,
                                MaximumDialect = SmbDialect.Smb2002
                            });
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb2002, client.NegotiatedDialect!.Value, "Expected loopback negotiation to clamp to SMB 2.0.2 when both sides cap the dialect range.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerNegotiateOptInSmb302WithoutEncryption",
                        displayName: "Client and server loopback negotiate SMB 3.0.2 without session encryption when both sides explicitly disable SMB3 encryption",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost(maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: false);
                            OpenCifsClientSession client = CreateClient(maximumDialect: SmbDialect.Smb302, preferEncryption: false);
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb302, client.NegotiatedDialect!.Value, "Expected loopback negotiation to select SMB 3.0.2.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                response.Capabilities,
                                "Expected the bounded SMB 3.0.2 loopback response to advertise the implemented large-MTU, leasing, and encryption capabilities.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerClampOptInNegotiationToSmb30WithoutEncryption",
                        displayName: "Client and server loopback clamp the bounded non-encrypted SMB3 slice to SMB 3.0 when the server caps below SMB 3.0.2",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost(maximumDialect: SmbDialect.Smb30, requireEncryptionForSmb3: false);
                            OpenCifsClientSession client = CreateClient(maximumDialect: SmbDialect.Smb302, preferEncryption: false);
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb30, client.NegotiatedDialect!.Value, "Expected loopback negotiation to clamp to SMB 3.0 when the server caps below SMB 3.0.2.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                response.Capabilities,
                                "Expected the bounded SMB 3.0 loopback response to advertise the implemented large-MTU, leasing, and encryption capabilities.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Loopback",
                        caseId: "ClientAndServerClampRequiredEncryptionSmb3NegotiationToSmb21WhenClientDisablesEncryption",
                        displayName: "Client and server loopback clamp required-encryption SMB3 negotiation to SMB 2.1 when the client disables encryption",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost server = CreateServerHost(maximumDialect: SmbDialect.Smb302, requireEncryptionForSmb3: true);
                            OpenCifsClientSession client = CreateClient(maximumDialect: SmbDialect.Smb302, preferEncryption: false);
                            Smb2NegotiateRequest request = client.CreateNegotiateRequest();
                            Smb2NegotiateResponse response = server.HandleNegotiate(request);
                            client.ApplyNegotiateResponse(response);

                            TestAssertions.Equal(SmbDialect.Smb21, client.NegotiatedDialect!.Value, "Expected loopback negotiation to clamp to SMB 2.1 when the server requires SMB3 encryption but the client does not advertise it.");
                            return Task.CompletedTask;
                        })
                });
        }

    }
}

