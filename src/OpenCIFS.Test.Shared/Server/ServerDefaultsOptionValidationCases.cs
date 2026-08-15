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
    internal static class ServerDefaultsOptionValidationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SecureDefaults",
                        displayName: "Server defaults enforce the planned secure posture",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerOptions options = new OpenCifsServerOptions();

                            if (options.BindPort != 4450)
                            {
                                throw new InvalidOperationException("Expected default bind port 4450.");
                            }

                            if (!options.RequireSigning)
                            {
                                throw new InvalidOperationException("Signing should be required by default.");
                            }

                            if (!options.RequireNtlmV2)
                            {
                                throw new InvalidOperationException("NTLMv2 should be required by default.");
                            }

                            if (options.AllowAnonymous)
                            {
                                throw new InvalidOperationException("Anonymous access should be disabled by default.");
                            }

                            if (options.EnableSmb1)
                            {
                                throw new InvalidOperationException("SMB1 should be disabled by default.");
                            }

                            if (!options.RequireEncryptionForSmb3)
                            {
                                throw new InvalidOperationException("SMB 3.x encryption should be required by default.");
                            }

                            if (options.MaximumCredits != 64)
                            {
                                throw new InvalidOperationException("Expected default maximum SMB2 credits 64.");
                            }

                            options.Validate();
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "InvalidSmb1RangeRejected",
                        displayName: "Server options reject an SMB1 minimum dialect when SMB1 is disabled",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerOptions options = new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Cifs10,
                                EnableSmb1 = false
                            };

                            try
                            {
                                options.Validate();
                            }
                            catch (ArgumentException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected Validate to reject SMB1 when it is disabled.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "Smb311MinimumRejectedWhenPreviewDisabled",
                        displayName: "Server options reject SMB 3.1.1 minimum dialect when preview is disabled",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerOptions options = new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb311,
                                MaximumDialect = SmbDialect.Smb311,
                                EnableSmb311Preview = false
                            };

                            try
                            {
                                options.Validate();
                            }
                            catch (ArgumentException)
                            {
                                return Task.CompletedTask;
                            }

                            throw new InvalidOperationException("Expected Validate to reject SMB 3.1.1 minimum dialect when preview is disabled.");
                        }),
            };
        }
    }
}
