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

    /// <summary>
    /// Shared Touchstone suites for server bootstrap validation.
    /// </summary>
    public static class ServerTestSuites
    {
        private const string DirectTcpPortReservationSemaphoreName = "OpenCIFS.DirectTcpTestPortReservation";
        private static readonly AsyncLocal<DirectTcpPortReservation?> _CurrentDirectTcpPortReservation = new AsyncLocal<DirectTcpPortReservation?>();

        /// <summary>
        /// All shared server test suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    ServerDefaultsSuite(),
                    ServerNegotiationSuite(),
                    ServerSessionTreeSuite(),
                    ServerEchoSuite(),
                    ServerCreditHeaderSuite(),
                    ServerChangeNotifySuite(),
                    ServerCompoundingSuite(),
                    ServerFileIoSuite(),
                    ServerLockingSuite(),
                    ServerOplockSuite(),
                    ServerLeaseSuite(),
                    ServerDurableHandleSuite(),
                    ServerIoctlSuite(),
                    ServerMetadataSuite(),
                    ServerDfsConfigurationSuite(),
                    ServerMutationSuite()
                };
            }
        }

        /// <summary>
        /// Build the server defaults suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerDefaultsSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Defaults",
                displayName: "Server bootstrap defaults",
                cases: new List<TestCaseDescriptor>
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

                            if (options.AuthenticationMechanism != OpenCifsAuthenticationMechanism.Ntlm)
                            {
                                throw new InvalidOperationException("Expected NTLM to remain the default server authentication mechanism.");
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
                        caseId: "SampleConfigurationExists",
                        displayName: "Sample configuration file exists",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string path = RepositoryPaths.FromRoot(Path.Combine("src", "Sample.OpenCifsServer", "sample.opencifs.server.json"));
                            FileAssertions.AssertExists(path);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleConfigurationDefaultsRemainSecure",
                        displayName: "Sample configuration defaults remain secure and match the planned tester posture",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SampleServerConfiguration configuration = new SampleServerConfiguration();
                            OpenCifsServerOptions options = configuration.ToServerOptions(Path.Combine(Path.GetTempPath(), "sample.opencifs.server.json"));

                            if (options.BindPort != 4450)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to default to bind port 4450.");
                            }

                            if (!options.RequireSigning || !options.RequireNtlmV2)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to require signing and NTLMv2.");
                            }

                            if (options.AuthenticationMechanism != OpenCifsAuthenticationMechanism.Ntlm || configuration.AuthenticationMechanism != OpenCifsAuthenticationMechanism.Ntlm)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to default to NTLM session setup.");
                            }

                            if (options.AllowAnonymous || options.EnableSmb1)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to disable anonymous access and SMB1.");
                            }

                            if (!options.RequireEncryptionForSmb3)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to require SMB 3.x encryption.");
                            }

                            if (configuration.AccountUserName != "alice" || configuration.AccountUserDomain != "WORKGROUP")
                            {
                                throw new InvalidOperationException("Expected the sample configuration to expose the documented test credentials.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleProgramWritesValidatesAndPrintsGuidanceWithOverrides",
                        displayName: "Sample program writes defaults, validates overrides, and prints deterministic tester guidance",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsSampleProgram_" + Guid.NewGuid().ToString("N"));
                            string configurationPath = Path.Combine(rootPath, "config", "sample.opencifs.server.json");

                            Directory.CreateDirectory(rootPath);

                            try
                            {
                                (int writeExitCode, string writeOutput, string writeError) = RunSampleProgram(
                                    "--config", configurationPath,
                                    "--write-default-config");

                                if (writeExitCode != 0)
                                {
                                    throw new InvalidOperationException("Expected the sample program to write the default configuration. Error: " + writeError);
                                }

                                FileAssertions.AssertExists(configurationPath);

                                if (!writeOutput.Contains(Path.GetFullPath(configurationPath), StringComparison.Ordinal))
                                {
                                    throw new InvalidOperationException("Expected the sample program to report the full configuration path after writing defaults.");
                                }

                                string expectedResolvedSharePath = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(configurationPath)!, "Shares", "Public"));

                                (int validateExitCode, string validateOutput, string validateError) = RunSampleProgram(
                                    "--config", configurationPath,
                                    "--validate-config",
                                    "--server-name", "fileserver",
                                    "--bind-address", "0.0.0.0",
                                    "--bind-port", "445",
                                    "--share-name", "public",
                                    "--share-path", Path.Combine("Shares", "Public"),
                                    "--account-username", "bob",
                                    "--account-domain", "LAB",
                                    "--account-password", "Secret123!",
                                    "--minimum-dialect", "Smb2002",
                                    "--maximum-dialect", "Smb311");

                                if (validateExitCode != 0)
                                {
                                    throw new InvalidOperationException("Expected the sample program to validate the effective configuration. Error: " + validateError);
                                }

                                if (!validateOutput.Contains("Bind endpoint: 0.0.0.0:445", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Share path: " + expectedResolvedSharePath, StringComparison.Ordinal) ||
                                    !validateOutput.Contains("UNC path: \\\\fileserver\\public", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Native Windows mount target: \\\\fileserver\\public", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Account password: <redacted>", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Validation: OK", StringComparison.Ordinal))
                                {
                                    throw new InvalidOperationException("Expected the validation report to include deterministic connection guidance and a redacted credential summary.");
                                }

                                (int printExitCode, string printOutput, string printError) = RunSampleProgram(
                                    "--config", configurationPath,
                                    "--print-config",
                                    "--server-name", "127.0.0.1",
                                    "--bind-address", "127.0.0.1",
                                    "--bind-port", "4450",
                                    "--share-name", "share",
                                    "--share-path", "SampleShare");

                                if (printExitCode != 0)
                                {
                                    throw new InvalidOperationException("Expected the sample program to print the effective configuration. Error: " + printError);
                                }

                                if (!printOutput.Contains("Direct-TCP endpoint: 127.0.0.1:4450", StringComparison.Ordinal) ||
                                    !printOutput.Contains("Native Windows mount note: Windows Explorer and net use require port 445;", StringComparison.Ordinal))
                                {
                                    throw new InvalidOperationException("Expected the configuration report to explain how custom ports affect native Windows mounting.");
                                }
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleProgramRejectsConflictingModesAndInvalidOverrides",
                        displayName: "Sample program rejects conflicting modes and invalid override values",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            (int conflictingExitCode, _, string conflictingError) = RunSampleProgram(
                                "--print-config",
                                "--validate-config");

                            if (conflictingExitCode == 0 || !conflictingError.Contains("Specify at most one of --write-default-config, --print-config, or --validate-config.", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the sample program to reject conflicting command modes.");
                            }

                            (int invalidExitCode, _, string invalidError) = RunSampleProgram(
                                "--bind-port", "not-a-number");

                            if (invalidExitCode == 0 || !invalidError.Contains("Invalid integer value for --bind-port: not-a-number.", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the sample program to reject invalid override values.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerShareIntrospectionReturnsImplicitAndExplicitShareSnapshots",
                        displayName: "Server share introspection returns implicit and explicit share snapshots across host, builder, configured-server, and application surfaces",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsShareIntrospection_" + Guid.NewGuid().ToString("N"));
                            string implicitSharePath = Path.Combine(rootPath, "legacy");
                            string publicSharePath = Path.Combine(rootPath, "public");
                            string archiveSharePath = Path.Combine(rootPath, "archive");
                            Directory.CreateDirectory(rootPath);

                            try
                            {
                                OpenCifsServerHost implicitHost = new OpenCifsServerHost(new OpenCifsServerOptions
                                {
                                    ShareName = "legacy",
                                    SharePath = implicitSharePath
                                });

                                IReadOnlyList<OpenCifsServerShareInfo> implicitShares = implicitHost.GetAvailableShares();
                                TestAssertions.Equal(1, implicitShares.Count, "Expected the host to expose one implicit share snapshot when no explicit shares are registered.");
                                TestAssertions.Equal("legacy", implicitShares[0].ShareName, "Expected the implicit share snapshot to expose the configured legacy share name.");
                                TestAssertions.Equal(Path.GetFullPath(implicitSharePath), implicitShares[0].RootPath, "Expected the implicit share snapshot to expose the configured root path.");
                                TestAssertions.True(implicitShares[0].IsImplicitOptionsShare, "Expected the host to mark the legacy fallback share as implicit.");
                                TestAssertions.True(implicitShares[0].SupportsFiles, "Expected the implicit share snapshot to expose file support.");
                                TestAssertions.True(implicitShares[0].SupportsDirectories, "Expected the implicit share snapshot to expose directory support.");
                                TestAssertions.False(implicitShares[0].SupportsNamedStreams, "Expected the implicit share snapshot to keep named streams disabled.");

                                OpenCifsServerBuilder builder = new OpenCifsServerBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER",
                                    ShareName = "legacy",
                                    SharePath = implicitSharePath
                                })
                                    .AddShare("public", share => share.UseLocalFileSystem(publicSharePath))
                                    .AddShare("archive", share => share.UseLocalFileSystem(archiveSharePath, createRootIfMissing: false));

                                IReadOnlyList<OpenCifsServerShareInfo> builderShares = builder.GetAvailableShares();
                                TestAssertions.Equal(2, builderShares.Count, "Expected the primary builder to expose both explicit shares.");
                                TestAssertions.Equal("public", builderShares[0].ShareName, "Expected the primary builder to preserve explicit share registration order.");
                                TestAssertions.Equal(Path.GetFullPath(publicSharePath), builderShares[0].RootPath, "Expected the primary builder to resolve explicit share paths.");
                                TestAssertions.False(builderShares[0].IsImplicitOptionsShare, "Expected explicit shares to stay non-implicit on the primary builder.");
                                TestAssertions.Equal("archive", builderShares[1].ShareName, "Expected the second explicit share snapshot to be exposed.");
                                TestAssertions.False(builderShares[1].CreateRootIfMissing, "Expected the explicit share snapshot to preserve CreateRootIfMissing.");

                                OpenCifsServer configuredServer = builder.Build();
                                IReadOnlyList<OpenCifsServerShareInfo> configuredServerShares = configuredServer.GetAvailableShares();
                                TestAssertions.Equal(2, configuredServerShares.Count, "Expected the configured server surface to preserve explicit share snapshots.");
                                TestAssertions.Equal("public", configuredServerShares[0].ShareName, "Expected the configured server surface to preserve the first explicit share.");
                                TestAssertions.Equal("archive", configuredServerShares[1].ShareName, "Expected the configured server surface to preserve the second explicit share.");

                                await using OpenCifsServerApplication application = configuredServer.BuildApplication();
                                IReadOnlyList<OpenCifsServerShareInfo> applicationShares = application.GetAvailableShares();
                                TestAssertions.Equal(2, applicationShares.Count, "Expected the managed application surface to preserve explicit share snapshots.");
                                TestAssertions.Equal("public", applicationShares[0].ShareName, "Expected the managed application surface to preserve the first explicit share.");
                                TestAssertions.Equal("archive", applicationShares[1].ShareName, "Expected the managed application surface to preserve the second explicit share.");

                                OpenCifsServerHost explicitHost = builder.BuildHost();
                                IReadOnlyList<OpenCifsServerShareInfo> explicitHostShares = explicitHost.GetAvailableShares();
                                TestAssertions.Equal(2, explicitHostShares.Count, "Expected the built host to expose the explicit share snapshots.");
                                TestAssertions.Equal("public", explicitHostShares[0].ShareName, "Expected the built host to expose the public share snapshot.");
                                TestAssertions.Equal("archive", explicitHostShares[1].ShareName, "Expected the built host to expose the archive share snapshot.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(rootPath);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerShareIntrospectionDoesNotIncludeImplicitLegacyShareWhenExplicitSharesExist",
                        displayName: "Server share introspection does not include the implicit legacy options share when explicit shares exist",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsExplicitShareIntrospection_" + Guid.NewGuid().ToString("N"));
                            string implicitSharePath = Path.Combine(rootPath, "legacy");
                            string explicitSharePath = Path.Combine(rootPath, "public");
                            Directory.CreateDirectory(rootPath);

                            try
                            {
                                OpenCifsServerOptions options = new OpenCifsServerOptions
                                {
                                    ShareName = "legacy",
                                    SharePath = implicitSharePath
                                };

                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(options);
                                builder.AddShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = explicitSharePath,
                                    CreateRootIfMissing = true
                                });

                                IReadOnlyList<OpenCifsServerShareInfo> builderShares = builder.GetAvailableShares();
                                TestAssertions.Equal(1, builderShares.Count, "Expected explicit share registration to suppress the implicit legacy share in builder introspection.");
                                TestAssertions.Equal("public", builderShares[0].ShareName, "Expected explicit share registration to preserve only the explicit share snapshot.");
                                TestAssertions.False(builderShares[0].IsImplicitOptionsShare, "Expected the explicit share snapshot to remain non-implicit.");

                                OpenCifsServerHost host = builder.BuildHost();
                                IReadOnlyList<OpenCifsServerShareInfo> hostShares = host.GetAvailableShares();
                                TestAssertions.Equal(1, hostShares.Count, "Expected the built host to suppress the implicit legacy share once explicit shares are registered.");
                                TestAssertions.Equal("public", hostShares[0].ShareName, "Expected the built host to expose only the explicit share snapshot.");

                                await using OpenCifsServerApplication application = builder.BuildApplication();
                                IReadOnlyList<OpenCifsServerShareInfo> applicationShares = application.GetAvailableShares();
                                TestAssertions.Equal(1, applicationShares.Count, "Expected the managed application surface to suppress the implicit legacy share once explicit shares are registered.");
                                TestAssertions.Equal("public", applicationShares[0].ShareName, "Expected the managed application surface to expose only the explicit share snapshot.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(rootPath);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerShareIntrospectionIncludesIpcWhenSrvsvcEndpointIsRegistered",
                        displayName: "Server share introspection includes IPC$ only when the bounded srvsvc named-pipe endpoint is registered",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsSrvsvcShareIntrospection_" + Guid.NewGuid().ToString("N"));
                            string legacySharePath = Path.Combine(rootPath, "legacy");
                            string explicitSharePath = Path.Combine(rootPath, "public");
                            Directory.CreateDirectory(rootPath);

                            try
                            {
                                OpenCifsServerHost implicitHost = new OpenCifsServerHost(new OpenCifsServerOptions
                                {
                                    ShareName = "legacy",
                                    SharePath = legacySharePath
                                });
                                implicitHost.RegisterNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoints.CreateSrvsvcShareEnumerationEndpoint());
                                IReadOnlyList<OpenCifsServerShareInfo> implicitHostShares = implicitHost.GetAvailableShares();
                                TestAssertions.Equal(2, implicitHostShares.Count, "Expected implicit host share introspection to expose the legacy share and IPC$ once the bounded srvsvc endpoint is registered.");
                                TestAssertions.True(implicitHostShares.Any(share => string.Equals(share.ShareName, "legacy", StringComparison.OrdinalIgnoreCase)), "Expected implicit host share introspection to preserve the legacy share.");
                                TestAssertions.True(implicitHostShares.Any(share => string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase)), "Expected implicit host share introspection to add IPC$ when named-pipe endpoints are registered.");

                                OpenCifsServerBuilder builder = new OpenCifsServerBuilder(new OpenCifsServerOptions
                                {
                                    ShareName = "legacy",
                                    SharePath = legacySharePath
                                })
                                    .AddShare("public", share => share.UseLocalFileSystem(explicitSharePath))
                                    .AddSrvsvcShareEnumerationEndpoint();

                                IReadOnlyList<OpenCifsServerShareInfo> builderShares = builder.GetAvailableShares();
                                TestAssertions.Equal(2, builderShares.Count, "Expected the primary server builder to expose the explicit data share plus IPC$ when srvsvc is registered.");
                                TestAssertions.True(builderShares.Any(share => string.Equals(share.ShareName, "public", StringComparison.OrdinalIgnoreCase)), "Expected the primary server builder to preserve the explicit data share.");
                                OpenCifsServerShareInfo builderIpcShare = builderShares.Single(share => string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase));
                                TestAssertions.False(builderIpcShare.IsImplicitOptionsShare, "Expected IPC$ to be reported as a concrete named-pipe share rather than as the legacy fallback share.");
                                TestAssertions.Equal(nameof(OpenCifsServerNamedPipeEndpoint), builderIpcShare.BackendKind, "Expected the IPC$ share snapshot to identify the bounded named-pipe endpoint surface.");
                                TestAssertions.False(builderIpcShare.SupportsFiles, "Expected the bounded IPC$ share snapshot not to claim ordinary file support.");
                                TestAssertions.False(builderIpcShare.SupportsDirectories, "Expected the bounded IPC$ share snapshot not to claim directory support.");

                                OpenCifsServer configuredServer = builder.Build();
                                IReadOnlyList<OpenCifsServerShareInfo> configuredServerShares = configuredServer.GetAvailableShares();
                                TestAssertions.Equal(2, configuredServerShares.Count, "Expected the configured server surface to preserve the explicit data share plus IPC$.");
                                TestAssertions.True(configuredServerShares.Any(share => string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase)), "Expected the configured server surface to preserve IPC$ when srvsvc is registered.");

                                OpenCifsServerHost explicitHost = builder.BuildHost();
                                IReadOnlyList<OpenCifsServerShareInfo> explicitHostShares = explicitHost.GetAvailableShares();
                                TestAssertions.Equal(2, explicitHostShares.Count, "Expected the built host to preserve the explicit data share plus IPC$.");
                                TestAssertions.True(explicitHostShares.Any(share => string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase)), "Expected the built host to preserve IPC$ when srvsvc is registered.");

                                await using OpenCifsServerApplication application = builder.BuildApplication();
                                IReadOnlyList<OpenCifsServerShareInfo> applicationShares = application.GetAvailableShares();
                                TestAssertions.Equal(2, applicationShares.Count, "Expected the managed application surface to preserve the explicit data share plus IPC$.");
                                TestAssertions.True(applicationShares.Any(share => string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase)), "Expected the managed application surface to preserve IPC$ when srvsvc is registered.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(rootPath);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerShareIntrospectionIncludesIpcForGenericNamedPipeEndpointsAndRejectsDuplicates",
                        displayName: "Server share introspection includes IPC$ for generic named-pipe endpoints and rejects duplicate endpoint names",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsEchoPipeShareIntrospection_" + Guid.NewGuid().ToString("N"));
                            string explicitSharePath = Path.Combine(rootPath, "public");
                            Directory.CreateDirectory(rootPath);

                            try
                            {
                                OpenCifsServerBuilder builder = new OpenCifsServerBuilder()
                                    .AddShare("public", share => share.UseLocalFileSystem(explicitSharePath))
                                    .AddUtf8EchoNamedPipeEndpoint();

                                TestAssertions.Throws<OpenCifsServerConfigurationException>(
                                    () => builder.AddUtf8EchoNamedPipeEndpoint(),
                                    "Expected duplicate bounded named-pipe endpoint names to be rejected on the primary server builder.");

                                IReadOnlyList<OpenCifsServerShareInfo> builderShares = builder.GetAvailableShares();
                                TestAssertions.Equal(2, builderShares.Count, "Expected the primary server builder to expose the explicit data share plus IPC$ when a generic named-pipe endpoint is registered.");
                                OpenCifsServerShareInfo ipcShare = builderShares.Single(share => string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase));
                                TestAssertions.Equal(nameof(OpenCifsServerNamedPipeEndpoint), ipcShare.BackendKind, "Expected the synthetic IPC$ share to identify the bounded named-pipe endpoint surface.");
                                TestAssertions.False(ipcShare.SupportsFiles, "Expected the synthetic IPC$ share not to claim ordinary file support for generic named-pipe endpoints.");
                                TestAssertions.False(ipcShare.SupportsDirectories, "Expected the synthetic IPC$ share not to claim ordinary directory support for generic named-pipe endpoints.");
                                TestAssertions.True(builderShares.Any(share => string.Equals(share.ShareName, "public", StringComparison.OrdinalIgnoreCase)), "Expected the explicit data share to remain visible alongside IPC$.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerBuildsManagedShareBackendsAndDoesNotClaimNamedStreamsOrAllowDoubleStart",
                        displayName: "Server builds managed share backends, does not claim named-stream support, and rejects double-start lifecycle control",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsManagedServer_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerApplication? application = null;

                            try
                            {
                                OpenCifsServerFileSystemShare share = new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                };
                                TestAssertions.True(share.Capabilities.SupportsFiles, "Expected the filesystem share backend to report file support.");
                                TestAssertions.True(share.Capabilities.SupportsDirectories, "Expected the filesystem share backend to report directory support.");
                                TestAssertions.True(share.Capabilities.SupportsMetadata, "Expected the filesystem share backend to report metadata support.");
                                TestAssertions.True(share.Capabilities.SupportsLocking, "Expected the filesystem share backend to report locking support.");
                                TestAssertions.True(share.Capabilities.SupportsNotifications, "Expected the filesystem share backend to report notification support.");
                                TestAssertions.False(share.Capabilities.SupportsNamedStreams, "Expected the filesystem share backend to keep named streams disabled in the current server surface.");

                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER",
                                    BindAddress = "127.0.0.1",
                                    BindPort = port
                                });
                                builder.AddShare(share);
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });

                                application = builder.BuildApplication();
                                TestAssertions.False(application.IsRunning, "Expected the managed server application to start in the stopped state.");

                                await application.StartAsync(token).ConfigureAwait(false);
                                TestAssertions.True(application.IsRunning, "Expected the managed server application to report a running listener after start.");
                                await WaitForTcpListenerStateAsync(port, shouldAcceptConnections: true, token).ConfigureAwait(false);

                                await TestAssertions.ThrowsAsync<OpenCifsServerStateException>(
                                    () => application.StartAsync(token),
                                    "Expected the managed server application to reject double-start attempts.").ConfigureAwait(false);

                                await application.StopAsync(token).ConfigureAwait(false);
                                TestAssertions.False(application.IsRunning, "Expected the managed server application to report a stopped listener after shutdown.");
                                await WaitForTcpListenerStateAsync(port, shouldAcceptConnections: false, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                if (application != null)
                                {
                                    await application.DisposeAsync().ConfigureAwait(false);
                                }

                                ReleaseDirectTcpPortReservation();
                                DeleteDirectoryForcefully(sharePath);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerPrimaryBuilderBuildsApplicationSurfaceWithLocalFileSystemShares",
                        displayName: "Server primary builder builds the aligned server and application surfaces with local filesystem share registration",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsPrimaryServer_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerApplication? application = null;

                            try
                            {
                                OpenCifsServerBuilder builder = new OpenCifsServerBuilder()
                                    .WithServerName("LAB-SERVER")
                                    .WithBindAddress("127.0.0.1")
                                    .WithBindPort(port)
                                    .WithSmb3EncryptionRequired(false)
                                    .AddAccount(new OpenCifsServerAccount
                                    {
                                        UserName = "alice",
                                        UserDomain = "WORKGROUP",
                                        Password = "Password123!"
                                    })
                                    .AddShare("public", share => share.UseLocalFileSystem(sharePath));

                                OpenCifsServerSettings builderSettings = builder.BuildSettings();
                                TestAssertions.Equal("LAB-SERVER", builderSettings.ServerName, "Expected BuildSettings to preserve the configured server name.");
                                TestAssertions.Equal("127.0.0.1", builderSettings.BindAddress, "Expected BuildSettings to preserve the configured bind address.");
                                TestAssertions.Equal(port, builderSettings.BindPort, "Expected BuildSettings to preserve the configured bind port.");
                                TestAssertions.False(builderSettings.RequireEncryptionForSmb3, "Expected BuildSettings to preserve the configured SMB 3.x encryption requirement.");

                                OpenCifsServer server = builder.Build();
                                TestAssertions.Equal("LAB-SERVER", server.Settings.ServerName, "Expected the configured server surface to preserve the configured server name.");
                                TestAssertions.Equal(port, server.Settings.BindPort, "Expected the configured server surface to preserve the configured bind port.");
                                TestAssertions.Equal(1, server.GetAvailableShares().Count, "Expected the configured server surface to expose the registered share snapshot.");
                                TestAssertions.Equal("public", server.GetAvailableShares()[0].ShareName, "Expected the configured server surface to expose the documented share name.");

                                application = server.BuildApplication();
                                TestAssertions.False(application.IsRunning, "Expected the aligned server application surface to start in the stopped state.");

                                await application.StartAsync(token).ConfigureAwait(false);
                                TestAssertions.True(application.IsRunning, "Expected the aligned server application surface to report a running listener after start.");
                                await WaitForTcpListenerStateAsync(port, shouldAcceptConnections: true, token).ConfigureAwait(false);

                                await application.StopAsync(token).ConfigureAwait(false);
                                TestAssertions.False(application.IsRunning, "Expected the aligned server application surface to report a stopped listener after shutdown.");
                                await WaitForTcpListenerStateAsync(port, shouldAcceptConnections: false, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                if (application != null)
                                {
                                    await application.DisposeAsync().ConfigureAwait(false);
                                }

                                ReleaseDirectTcpPortReservation();
                                DeleteDirectoryForcefully(sharePath);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerApplicationSurfaceExposesTryAsyncLifecycleCompanionsAndTypedListenerFailures",
                        displayName: "Server application surface exposes TryAsync lifecycle companions and typed listener-state failures",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            if (typeof(OpenCifsServerApplication).GetMethod(nameof(OpenCifsServerApplication.TryRunAsync)) == null ||
                                typeof(OpenCifsServerApplication).GetMethod(nameof(OpenCifsServerApplication.TryStartAsync)) == null ||
                                typeof(OpenCifsServerApplication).GetMethod(nameof(OpenCifsServerApplication.TryStopAsync)) == null)
                            {
                                throw new InvalidOperationException("Expected the managed server application surface to expose bounded Try...Async lifecycle companions.");
                            }

                            if (typeof(OpenCifsServerResult).GetProperty(nameof(OpenCifsServerResult.IsSuccess)) == null ||
                                typeof(OpenCifsServerResult).GetProperty(nameof(OpenCifsServerResult.Exception)) == null)
                            {
                                throw new InvalidOperationException("Expected the managed server result envelope to expose success and typed exception members.");
                            }

                            string firstSharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerTrySurface_" + Guid.NewGuid().ToString("N"));
                            string secondSharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerTrySurface_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(firstSharePath);
                            Directory.CreateDirectory(secondSharePath);
                            int port = AllocateTcpPort();
                            OpenCifsServerApplication? firstApplication = null;
                            OpenCifsServerApplication? secondApplication = null;

                            try
                            {
                                OpenCifsServerBuilder firstBuilder = new OpenCifsServerBuilder()
                                    .WithServerName("LAB-SERVER")
                                    .WithBindAddress("127.0.0.1")
                                    .WithBindPort(port)
                                    .AddAccount(new OpenCifsServerAccount
                                    {
                                        UserName = "alice",
                                        UserDomain = "WORKGROUP",
                                        Password = "Password123!"
                                    })
                                    .AddShare("public", share => share.UseLocalFileSystem(firstSharePath));
                                firstApplication = firstBuilder.BuildApplication();

                                OpenCifsServerResult firstStartResult = await firstApplication.TryStartAsync(token).ConfigureAwait(false);
                                TestAssertions.True(firstStartResult.IsSuccess, "Expected TryStartAsync to succeed for the first managed server application.");

                                OpenCifsServerResult duplicateStartResult = await firstApplication.TryStartAsync(token).ConfigureAwait(false);
                                TestAssertions.False(duplicateStartResult.IsSuccess, "Expected TryStartAsync to report a failure envelope for duplicate starts.");
                                TestAssertions.True(duplicateStartResult.Exception is OpenCifsServerStateException, "Expected duplicate managed start failures to preserve the typed server-state exception.");

                                OpenCifsServerBuilder secondBuilder = new OpenCifsServerBuilder()
                                    .WithServerName("LAB-SERVER")
                                    .WithBindAddress("127.0.0.1")
                                    .WithBindPort(port)
                                    .AddAccount(new OpenCifsServerAccount
                                    {
                                        UserName = "alice",
                                        UserDomain = "WORKGROUP",
                                        Password = "Password123!"
                                    })
                                    .AddShare("public", share => share.UseLocalFileSystem(secondSharePath));
                                secondApplication = secondBuilder.BuildApplication();

                                OpenCifsServerResult secondStartResult = await secondApplication.TryStartAsync(token).ConfigureAwait(false);
                                TestAssertions.False(secondStartResult.IsSuccess, "Expected TryStartAsync to report a failure envelope when the listener port is already in use.");
                                TestAssertions.True(secondStartResult.Exception is OpenCifsServerStateException, "Expected bind failures on the managed server application surface to preserve the typed server-state exception.");

                                OpenCifsServerResult firstStopResult = await firstApplication.TryStopAsync(token).ConfigureAwait(false);
                                TestAssertions.True(firstStopResult.IsSuccess, "Expected TryStopAsync to succeed for a running managed server application.");

                                await firstApplication.DisposeAsync().ConfigureAwait(false);
                                OpenCifsServerResult disposedStartResult = await firstApplication.TryStartAsync(token).ConfigureAwait(false);
                                TestAssertions.False(disposedStartResult.IsSuccess, "Expected TryStartAsync to report a failure envelope after disposal.");
                                TestAssertions.True(disposedStartResult.Exception is OpenCifsServerStateException, "Expected disposed managed-server lifecycle calls to preserve the typed server-state exception.");
                                firstApplication = null;
                            }
                            finally
                            {
                                if (secondApplication != null)
                                {
                                    await secondApplication.DisposeAsync().ConfigureAwait(false);
                                }

                                if (firstApplication != null)
                                {
                                    await firstApplication.DisposeAsync().ConfigureAwait(false);
                                }

                                ReleaseDirectTcpPortReservation();
                                DeleteDirectoryForcefully(firstSharePath);
                                DeleteDirectoryForcefully(secondSharePath);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerPublicSurfaceExposesTypedConfigurationExceptions",
                        displayName: "Server public surface exposes typed configuration exceptions for representative builder failures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHostBuilder duplicateShareBuilder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                            {
                                ServerName = "LAB-SERVER"
                            });
                            duplicateShareBuilder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                            {
                                ShareName = "public",
                                RootPath = Path.Combine(Path.GetTempPath(), "OpenCifsTypedServerException_public"),
                                CreateRootIfMissing = true
                            });

                            TestAssertions.Throws<OpenCifsServerConfigurationException>(
                                () => duplicateShareBuilder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "PUBLIC",
                                    RootPath = Path.Combine(Path.GetTempPath(), "OpenCifsTypedServerException_public_2"),
                                    CreateRootIfMissing = true
                                }),
                                "Expected duplicate share registration to raise a typed server-configuration exception.");

                            OpenCifsServerBuilder serverBuilder = new OpenCifsServerBuilder();
                            TestAssertions.Throws<OpenCifsServerConfigurationException>(
                                () => serverBuilder.AddShare("orphaned", share => { }),
                                "Expected a share builder without a backing provider to raise a typed server-configuration exception.");

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsTypedServerException_direct_host");
                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions());
                            host.RegisterShare(new OpenCifsServerFileSystemShare
                            {
                                ShareName = "public",
                                RootPath = sharePath,
                                CreateRootIfMissing = true
                            });

                            TestAssertions.Throws<OpenCifsServerConfigurationException>(
                                () => host.RegisterShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "PUBLIC",
                                    RootPath = sharePath + "_2",
                                    CreateRootIfMissing = true
                                }),
                                "Expected duplicate direct host share registration to raise a typed server-configuration exception.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "ServerSuitesExposePositiveAndNegativeVariants",
                        displayName: "Server shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(All, "Server");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server negotiate suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerNegotiationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Negotiate",
                displayName: "Server negotiate handling",
                cases: new List<TestCaseDescriptor>
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
                        caseId: "DirectTcpServerBridgesSmb1MultiProtocolNegotiateToSmb2",
                        displayName: "Direct-TCP server bridges SMB1 multi-protocol negotiate into an SMB2 negotiate response",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(port, token).ConfigureAwait(false);

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb1NegotiateRequest request = new Smb1NegotiateRequest
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

                                await WriteDirectTcpFrameAsync(stream, request.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);

                                TestAssertions.Equal(1, responsePacket.Entries.Count, "Expected a single SMB2 negotiate response entry.");
                                TestAssertions.Equal(Smb2Command.Negotiate, responsePacket.Entries[0].Header.Command, "Expected the bridged response command to be SMB2 negotiate.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the bridged response status to be success.");
                                TestAssertions.Equal(0UL, responsePacket.Entries[0].Header.MessageId, "Expected the bridged SMB2 negotiate response to remain bound to sequence number zero.");

                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);
                                TestAssertions.Equal(SmbDialect.Smb21, response.Dialect, "Expected the bridged SMB1 negotiate request to resolve to the highest implemented SMB 2.x dialect.");
                                TestAssertions.True((response.SecurityMode & Smb2SecurityMode.SigningEnabled) != 0, "Expected the bridged SMB2 negotiate response to keep signing enabled.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerBridgesSmb1MultiProtocolNegotiateToOptInSmb302",
                        displayName: "Direct-TCP server bridges SMB1 multi-protocol negotiate into an opt-in SMB 3.0.2 negotiate response",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                port,
                                requireEncryptionForSmb3: false,
                                token).ConfigureAwait(false);

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb1NegotiateRequest request = new Smb1NegotiateRequest
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

                                await WriteDirectTcpFrameAsync(stream, request.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);

                                TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the opt-in bridged SMB1 negotiate request to resolve to SMB 3.0.2.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerAcceptsSmb311StyleNegotiateAndClampsToSmb302",
                        displayName: "Direct-TCP server accepts an SMB 3.1.1-style negotiate request shape and clamps selection to SMB 3.0.2",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                port,
                                requireEncryptionForSmb3: false,
                                token).ConfigureAwait(false);

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb2NegotiateRequest request = new Smb2NegotiateRequest
                                {
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                    ClientGuid = Guid.NewGuid(),
                                    Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 },
                                    NegotiateContextCount = 1,
                                    NegotiateContextData = new byte[]
                                    {
                                        0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                                    }
                                };
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2),
                                            request.ToByteArray())
                                    });

                                await WriteDirectTcpFrameAsync(stream, requestPacket.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);

                                TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the SMB 3.1.1-style request shape to clamp to the highest implemented SMB 3.0.2 dialect.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
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
                        caseId: "ServerNegotiatesRequiredEncryptionSmb302ForSmb311StyleRequestShape",
                        displayName: "Server negotiate handling accepts an SMB 3.1.1-style request shape for required-encryption SMB 3.0.2 negotiation",
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
                                Dialects = new[] { SmbDialect.Smb302, SmbDialect.Smb311 },
                                NegotiateContextCount = 1,
                                NegotiateContextData = new byte[]
                                {
                                    0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                                }
                            };

                            Smb2NegotiateResponse response = host.HandleNegotiate(request);

                            TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the required-encryption server to accept the SMB 3.1.1-style request shape and negotiate SMB 3.0.2.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewCapturesNetnameContextAndExposesItForInspection",
                        displayName: "Server SMB 3.1.1 preview captures the client NETNAME context and exposes it for inspection",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x01, 0x02 }
                            }.ToByteArray();
                            byte[] netnamePayload = new NetnameNegotiateContext
                            {
                                ServerName = "files.contoso.test"
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });
                            TestAssertions.True(previewHost.GetReceivedClientNetname() == null, "Expected the host to start with no captured NETNAME.");

                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.Parse("FEDCBA98-7654-3210-FEDC-BA9876543210"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.Netname, Payload = netnamePayload }
                            });

                            previewHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal("files.contoso.test", previewHost.GetReceivedClientNetname()!, "Expected the SMB 3.1.1 preview server to capture the client-supplied NETNAME server name for inspection.");

                            OpenCifsServerHost defaultHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = false,
                                RequireEncryptionForSmb3 = false
                            });
                            defaultHost.HandleNegotiate(previewRequest);
                            TestAssertions.True(defaultHost.GetReceivedClientNetname() == null, "Expected the default opt-out server to leave the captured NETNAME empty.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewEmitsTypedResponseContextsAndPreservesPreauthSelectionOnSmb311DialectMatch",
                        displayName: "Server SMB 3.1.1 preview emits typed Preauth and Encryption response contexts and preserves the selected algorithms when negotiating SMB 3.1.1",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xC0, 0xDE, 0xCA, 0xFE }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray();
                            byte[] signingPayload = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[]
                                {
                                    SigningAlgorithmId.AesGmac,
                                    SigningAlgorithmId.AesCmac,
                                    SigningAlgorithmId.HmacSha256
                                }
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });

                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.Parse("ABCDEF01-2345-6789-ABCD-EF0123456789"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload }
                            });

                            Smb2NegotiateResponse previewResponse = previewHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal(SmbDialect.Smb311, previewResponse.Dialect, "Expected the preview server to negotiate SMB 3.1.1.");
                            TestAssertions.Equal((ushort)3, previewResponse.NegotiateContextCount, "Expected the preview server response to carry three typed negotiate-context entries.");

                            Smb2NegotiateContextEntry[] decodedResponseEntries = previewResponse.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(3, decodedResponseEntries.Length, "Expected three decoded response negotiate-context entries.");

                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedResponseEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Server should select SHA-512 preauth integrity in the response.");
                            TestAssertions.Equal(32, decodedPreauth.Salt.Length, "Server should generate a 32-byte preauth response salt.");

                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedResponseEntries[1].Payload);
                            TestAssertions.Equal(1, decodedEncryption.Ciphers.Length, "Server should select a single cipher in the response.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, decodedEncryption.Ciphers[0], "Server should prefer AES-128-GCM as the bounded cipher when offered.");

                            SigningCapabilities decodedSigning = SigningCapabilities.ReadFrom(decodedResponseEntries[2].Payload);
                            TestAssertions.Equal(1, decodedSigning.SigningAlgorithms.Length, "Server should select a single signing algorithm in the response.");
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, decodedSigning.SigningAlgorithms[0], "Server should select AES-GMAC as the bounded signing algorithm when offered.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewNegotiatesSmb311WhenBothOptInAndFallsBackToSmb302WhenMissingServerOptIn",
                        displayName: "Server SMB 3.1.1 preview negotiates SMB 3.1.1 when both sides opt in and falls back to SMB 3.0.2 when the server is missing the opt-in",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x10, 0x20, 0x30, 0x40 }
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = true,
                                RequireEncryptionForSmb3 = false
                            });

                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                ClientGuid = Guid.Parse("11223344-5566-7788-99AA-BBCCDDEEFF00"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload }
                            });

                            Smb2NegotiateResponse previewResponse = previewHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal(SmbDialect.Smb311, previewResponse.Dialect, "Expected the preview-opted-in server to select SMB 3.1.1 when the client also opts in.");

                            OpenCifsServerHost defaultHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                EnableSmb311Preview = false,
                                RequireEncryptionForSmb3 = false
                            });
                            Smb2NegotiateResponse defaultResponse = defaultHost.HandleNegotiate(previewRequest);
                            TestAssertions.Equal(SmbDialect.Smb302, defaultResponse.Dialect, "Expected the default opt-out server to keep tolerance behavior and select SMB 3.0.2 against a 3.1.1 preview client.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerSmb311PreviewAccumulatesPreauthIntegrityTranscriptAcrossNegotiate",
                        displayName: "Server SMB 3.1.1 preview accumulates the preauth integrity transcript across the negotiate request and response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost defaultHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true
                            });
                            defaultHost.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302 }
                            });
                            byte[]? defaultHash = defaultHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(defaultHash == null, "Expected the default opt-out server to leave the preauth hash unallocated.");

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }
                            }.ToByteArray();

                            OpenCifsServerHost previewHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true,
                                EnableSmb311Preview = true
                            });
                            Smb2NegotiateRequest previewRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.Parse("E0A4B6F8-1234-4567-89AB-CDEF01234567"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            previewRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload }
                            });

                            Smb2NegotiateResponse previewResponse = previewHost.HandleNegotiate(previewRequest);
                            byte[]? initialHash = previewHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(initialHash != null, "Expected the preview opt-in server to allocate the preauth hash accumulator after a 3.1.1-shaped request.");
                            TestAssertions.Equal(64, initialHash!.Length, "Expected the SHA-512 preauth hash to be 64 bytes wide.");

                            byte[] zeros = new byte[64];
                            TestAssertions.SequenceEqual(zeros, initialHash, "Expected the server preauth hash to start at all zeros per MS-SMB2.");

                            Smb2Header requestHeader = new Smb2Header
                            {
                                Command = Smb2Command.Negotiate,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.None,
                                MessageId = 0,
                                Signature = new byte[16]
                            };
                            previewHost.AppendPreauthMessageBytes(requestHeader, previewRequest.ToByteArray());
                            byte[]? afterRequest = previewHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(afterRequest != null && !afterRequest.AsSpan().SequenceEqual(zeros), "Expected the server preauth hash to advance after appending the negotiate request.");

                            Smb2Header responseHeader = new Smb2Header
                            {
                                Command = Smb2Command.Negotiate,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.ServerToRedir,
                                MessageId = requestHeader.MessageId,
                                Signature = new byte[16]
                            };
                            previewHost.AppendPreauthMessageBytes(responseHeader, previewResponse.ToByteArray());
                            byte[]? afterResponse = previewHost.GetCurrentPreauthIntegrityHash();
                            TestAssertions.True(afterResponse != null && !afterResponse.AsSpan().SequenceEqual(afterRequest!), "Expected the server preauth hash to advance again after appending the negotiate response.");
                            TestAssertions.Equal(64, afterResponse!.Length, "Expected the server preauth hash to remain 64 bytes wide after the response.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "ServerAcceptsTypedSmb311NegotiateContextRequestAndPreservesEntriesAfterWireRoundTrip",
                        displayName: "Server accepts a typed SMB 3.1.1 negotiate-context request and preserves typed entries after a wire round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray();
                            byte[] netnamePayload = new NetnameNegotiateContext
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName
                            }.ToByteArray();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = true
                            });
                            Smb2NegotiateRequest typedRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.Parse("E0A4B6F8-1234-4567-89AB-CDEF01234567"),
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            typedRequest.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.Netname, Payload = netnamePayload }
                            });

                            byte[] wireBytes = typedRequest.ToByteArray();
                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(wireBytes);
                            TestAssertions.Equal((ushort)3, parsedRequest.NegotiateContextCount, "Wire round-trip should preserve negotiate-context count.");
                            Smb2NegotiateContextEntry[] decodedEntries = parsedRequest.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(3, decodedEntries.Length, "Wire round-trip should preserve negotiate-context entry count.");

                            Smb2NegotiateResponse response = host.HandleNegotiate(parsedRequest);
                            TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the server to negotiate SMB 3.0.2 against a typed SMB 3.1.1 negotiate-context request shape.");

                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Decoded preauth hash algorithm should round-trip through the server's negotiate-context tolerance.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, decodedEncryption.Ciphers[0], "Decoded encryption cipher should round-trip through the server's negotiate-context tolerance.");
                            NetnameNegotiateContext decodedNetname = NetnameNegotiateContext.ReadFrom(decodedEntries[2].Payload);
                            TestAssertions.Equal(TestEnvironmentDefaults.DefaultServerName, decodedNetname.ServerName, "Decoded NETNAME server name should round-trip through the server's negotiate-context tolerance.");

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
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerNegotiatesRequiredEncryptionSmb302ForSmb311StyleRequestShape",
                        displayName: "Direct-TCP server negotiates required-encryption SMB 3.0.2 for an SMB 3.1.1-style request shape",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                port,
                                requireEncryptionForSmb3: true,
                                token).ConfigureAwait(false);

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb2NegotiateRequest request = new Smb2NegotiateRequest
                                {
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                    ClientGuid = Guid.NewGuid(),
                                    Dialects = new[] { SmbDialect.Smb302, SmbDialect.Smb311 },
                                    NegotiateContextCount = 1,
                                    NegotiateContextData = new byte[]
                                    {
                                        0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                                    }
                                };
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2),
                                            request.ToByteArray())
                                    });

                                await WriteDirectTcpFrameAsync(stream, requestPacket.ToByteArray(), token).ConfigureAwait(false);
                                byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);
                                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
                                Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(responsePacket.Entries[0].Payload);

                                TestAssertions.Equal(SmbDialect.Smb302, response.Dialect, "Expected the required-encryption direct-TCP server to accept the SMB 3.1.1-style request shape and negotiate SMB 3.0.2.");
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Negotiate",
                        caseId: "DirectTcpServerRejectsSmb1NegotiateWithoutSmb2002Dialect",
                        displayName: "Direct-TCP server closes the connection when an SMB1 multi-protocol negotiate omits SMB 2.002",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(port, token).ConfigureAwait(false);

                            try
                            {
                                using TcpClient tcpClient = new TcpClient();
                                await tcpClient.ConnectAsync(IPAddress.Loopback, port, token).ConfigureAwait(false);
                                using NetworkStream stream = tcpClient.GetStream();
                                Smb1NegotiateRequest request = new Smb1NegotiateRequest
                                {
                                    Dialects = new string[]
                                    {
                                        "NT LM 0.12"
                                    }
                                };

                                await WriteDirectTcpFrameAsync(stream, request.ToByteArray(), token).ConfigureAwait(false);
                                byte[]? responsePayload = await TryReadDirectTcpFramePayloadAsync(stream, token).ConfigureAwait(false);

                                if (responsePayload != null)
                                {
                                    throw new InvalidOperationException("Expected the direct-TCP server to close the connection without responding when SMB 2.002 is absent from the SMB1 negotiate preamble.");
                                }
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        })
                });
        }

        /// <summary>
        /// Build the server session and tree suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerSessionTreeSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.SessionTree",
                displayName: "Server session and tree handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerAuthenticatesKnownAccountAndHandlesTreeLifecycle",
                        displayName: "Server issues a challenge, authenticates a known account, and handles tree lifecycle operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            Smb2SessionSetupRequest initialRequest = CreateInitialSessionSetupRequest("alice", "WORKGROUP");
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, initialRequest);

                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the first session-setup leg to return a challenge.");
                            TestAssertions.True(challengeResult.SessionId != 0, "Expected the server to assign a non-zero session identifier.");

                            Smb2SessionSetupRequest authenticateRequest = CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult);
                            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);

                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected the server to accept valid NTLMv2 credentials.");

                            SpnegoNegTokenResp successToken = SpnegoTokenCodec.DecodeNegTokenResp(successResult.Response.SecurityBuffer);
                            TestAssertions.Equal(SpnegoNegState.AcceptCompleted, successToken.NegotiationState!.Value, "Expected the server to complete SPNEGO after authentication.");
                            TestAssertions.True(successToken.MechanismListMic == null, "Expected the legacy OpenCIFS NTLM SPNEGO success token to omit the mechListMIC field in the bounded compatibility path.");

                            Smb2TreeConnectRequest treeConnectRequest = new Smb2TreeConnectRequest
                            {
                                Path = "\\\\LAB-SERVER\\public"
                            };
                            OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(successResult.SessionId, treeConnectRequest);

                            TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected the authenticated session to connect to the configured share.");
                            TestAssertions.True(treeConnectResult.TreeId != 0, "Expected the server to assign a non-zero tree identifier.");

                            OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = host.HandleTreeDisconnect(
                                successResult.SessionId,
                                treeConnectResult.TreeId,
                                new Smb2TreeDisconnectRequest());
                            TestAssertions.Equal(NtStatus.Success, treeDisconnectResult.Status, "Expected tree disconnect to succeed.");

                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = host.HandleLogoff(successResult.SessionId, new Smb2LogoffRequest());
                            TestAssertions.Equal(NtStatus.Success, logoffResult.Status, "Expected logoff to succeed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerSignsLogoffResponseAfterSessionCleanupAndRejectsLaterSessionReuse",
                        displayName: "Server signs a logoff response after session cleanup and rejects later session reuse",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            (ulong sessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(host);
                            Smb2LogoffRequest logoffRequest = new Smb2LogoffRequest();
                            Smb2Header signedLogoffHeader = CreateRequestHeader(
                                Smb2Command.Logoff,
                                messageId: 0,
                                flags: Smb2HeaderFlags.Signed,
                                sessionId: sessionId);
                            Smb2HeaderValidator.Validate(signedLogoffHeader);

                            byte[] signedLogoffRequestBytes = CreateSignedPacketBytes(signedLogoffHeader, logoffRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket signedLogoffRequestPacket = Smb2CompoundPacket.ReadFrom(signedLogoffRequestBytes);
                            host.ValidateRequestPacket(signedLogoffRequestPacket, signedLogoffRequestBytes);
                            host.ValidateAndAcceptRequestHeader(signedLogoffHeader, Smb2Command.Logoff, expectedSessionId: sessionId);

                            OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = host.HandleLogoff(sessionId, logoffRequest);
                            TestAssertions.Equal(NtStatus.Success, logoffResult.Status, "Expected logoff to succeed before response finalization.");

                            Smb2Header responseHeader = host.CreateResponseHeader(signedLogoffHeader, logoffResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, logoffResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                            Smb2Header parsedResponseHeader = parsedResponsePacket.Entries[0].Header;

                            TestAssertions.True(
                                (parsedResponseHeader.Flags & Smb2HeaderFlags.Signed) != 0,
                                "Expected the logoff response to preserve the Signed flag when the client signed the request.");

                            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
                            byte[] unsignedResponseBytes = (byte[])responseBytes.Clone();
                            Array.Clear(unsignedResponseBytes, 48, 16);
                            TestAssertions.True(
                                signer.Verify(unsignedResponseBytes, signingKey, ReadOnlySpan<byte>.Empty, parsedResponseHeader.Signature),
                                "Expected the finalized logoff response signature to verify with the authenticated session signing key.");

                            OpenCifsServerOperationResult<Smb2EchoResponse> postLogoffEchoResult = host.HandleEcho(sessionId, new Smb2EchoRequest());
                            TestAssertions.Equal(
                                NtStatus.AccessDenied,
                                postLogoffEchoResult.Status,
                                "Expected the server to deny further session use after logoff even though the response stayed signable.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerCompletesStandardSpnegoWrappedNtlmSessionSetup",
                        displayName: "Server completes a standard SPNEGO-wrapped NTLM session setup with an accept-completed final token",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            Smb2SessionSetupRequest initialRequest = CreateStandardInitialSessionSetupRequest("alice", "WORKGROUP");
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, initialRequest);

                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the first standard NTLM session-setup leg to return a challenge.");
                            TestAssertions.True(challengeResult.SessionId != 0, "Expected the server to assign a non-zero standard session identifier.");

                            SpnegoNegTokenResp challengeToken = SpnegoTokenCodec.DecodeNegTokenResp(challengeResult.Response.SecurityBuffer);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, challengeToken.NegotiationState!.Value, "Expected the standard challenge leg to return an incomplete SPNEGO token.");
                            TestAssertions.True(challengeToken.ResponseToken != null && challengeToken.ResponseToken.Length != 0, "Expected the standard challenge leg to carry an NTLM challenge token.");

                            Smb2SessionSetupRequest authenticateRequest = CreateStandardAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult);
                            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(challengeResult.SessionId, authenticateRequest);

                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected the server to accept valid standard SPNEGO-wrapped NTLM credentials.");
                            TestAssertions.True(successResult.Response.SecurityBuffer.Length != 0, "Expected the standard NTLM success leg to carry a final SPNEGO token.");

                            SpnegoNegTokenResp successToken = SpnegoTokenCodec.DecodeNegTokenResp(successResult.Response.SecurityBuffer);
                            TestAssertions.Equal(SpnegoNegState.AcceptCompleted, successToken.NegotiationState!.Value, "Expected the standard NTLM success leg to complete SPNEGO.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, successToken.SupportedMechanism, "Expected the standard NTLM success leg to identify NTLM as the selected mechanism.");
                            TestAssertions.True(successToken.MechanismListMic != null && successToken.MechanismListMic.Length == 16, "Expected the standard NTLM success leg to include a mechListMIC when the authenticate leg carries an NTLM MIC.");

                            SpnegoNegTokenResp authenticateToken = SpnegoTokenCodec.DecodeNegTokenResp(authenticateRequest.SecurityBuffer);
                            NtlmAuthenticateMessage authenticateMessage = NtlmAuthenticateMessage.ReadFrom(authenticateToken.ResponseToken!);
                            byte[] expectedMechanismListMic = CreateExpectedSpnegoMechanismListMic(
                                new[] { SpnegoMechanismOid.Ntlm },
                                authenticateMessage.Flags,
                                ExtractSessionBaseKey("alice", "WORKGROUP", "Password123!", challengeResult));
                            TestAssertions.SequenceEqual(expectedMechanismListMic, successToken.MechanismListMic!, "Expected the standard NTLM success leg mechListMIC to stay stable.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerReturnsNotSupportedForKerberosUntilImplemented",
                        displayName: "Server returns STATUS_NOT_SUPPORTED for Kerberos session setup until the Kerberos path is implemented",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = "LAB-SERVER",
                                AuthenticationMechanism = OpenCifsAuthenticationMechanism.Kerberos
                            });
                            host.RegisterAccount(new OpenCifsServerAccount
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP",
                                Password = "Password123!"
                            });

                            Smb2SessionSetupRequest request = new Smb2SessionSetupRequest
                            {
                                Flags = 0,
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.None,
                                Channel = 0,
                                PreviousSessionId = 0,
                                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenInit(new SpnegoNegTokenInit
                                {
                                    MechanismTypes = OpenCifsAuthenticationMechanismCatalog.GetSpnegoMechanismOids(OpenCifsAuthenticationMechanism.Kerberos)
                                })
                            };

                            OpenCifsServerSessionSetupResult result = host.HandleSessionSetup(0, request);
                            TestAssertions.Equal(NtStatus.NotSupported, result.Status, "Expected the bounded Kerberos groundwork path to return STATUS_NOT_SUPPORTED until Kerberos token handling is implemented.");
                            TestAssertions.Equal(0uL, result.SessionId, "Expected the bounded Kerberos groundwork path to avoid allocating a session.");
                            TestAssertions.Equal(0, result.Response.SecurityBuffer.Length, "Expected the bounded Kerberos groundwork path to return an empty security buffer.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRoutesExplicitShareRegistrationsAcrossSeparateRoots",
                        displayName: "Server routes authenticated tree connects across explicit share registrations and persists creates in the selected root",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsServerShares_" + Guid.NewGuid().ToString("N"));
                            string legacyPath = Path.Combine(rootPath, "legacy");
                            string publicPath = Path.Combine(rootPath, "public");
                            string archivePath = Path.Combine(rootPath, "archive");
                            Directory.CreateDirectory(publicPath);
                            Directory.CreateDirectory(archivePath);

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER",
                                    ShareName = "legacy",
                                    SharePath = legacyPath
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = publicPath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "archive",
                                    RootPath = archivePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                ulong sessionId = AuthenticateSession(host);
                                OpenCifsServerTreeConnectResult archiveTreeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\archive"
                                    });

                                TestAssertions.Equal(NtStatus.Success, archiveTreeConnectResult.Status, "Expected the server to route the tree connect to an explicitly registered share.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    archiveTreeConnectResult.TreeId,
                                    CreateFileCreateRequest("builder.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected create to succeed on the selected registered share.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(
                                    sessionId,
                                    archiveTreeConnectResult.TreeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected close to succeed after the routed create.");

                                TestAssertions.True(File.Exists(Path.Combine(archivePath, "builder.txt")), "Expected the created file to land in the selected registered share root.");
                                TestAssertions.False(File.Exists(Path.Combine(publicPath, "builder.txt")), "Expected the routed create to avoid sibling registered share roots.");

                                OpenCifsServerTreeConnectResult legacyFallbackResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\legacy"
                                    });
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, legacyFallbackResult.Status, "Expected explicit share registrations to suppress the implicit legacy options share.");
                            }
                            finally
                            {
                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRejectsBadPasswordAndUnauthenticatedTreeConnect",
                        displayName: "Server rejects invalid credentials and unauthenticated tree access",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            OpenCifsServerTreeConnectResult unauthenticatedTreeConnectResult = host.HandleTreeConnect(
                                sessionId: 0,
                                request: new Smb2TreeConnectRequest
                                {
                                    Path = "\\\\LAB-SERVER\\public"
                                });
                            TestAssertions.Equal(NtStatus.AccessDenied, unauthenticatedTreeConnectResult.Status, "Expected unauthenticated tree connect to be denied.");

                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                            Smb2SessionSetupRequest badPasswordRequest = CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "WrongPassword!", challengeResult);
                            OpenCifsServerSessionSetupResult failedAuthenticationResult = host.HandleSessionSetup(challengeResult.SessionId, badPasswordRequest);

                            TestAssertions.Equal(NtStatus.AccessDenied, failedAuthenticationResult.Status, "Expected the server to reject an invalid password.");

                            OpenCifsServerTreeConnectResult postFailureTreeConnectResult = host.HandleTreeConnect(
                                challengeResult.SessionId,
                                new Smb2TreeConnectRequest
                                {
                                    Path = "\\\\LAB-SERVER\\public"
                                });
                            TestAssertions.Equal(NtStatus.AccessDenied, postFailureTreeConnectResult.Status, "Expected the failed session to lose tree access.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRejectsUnknownShareAfterAuthentication",
                        displayName: "Server returns ObjectNameNotFound for unknown shares after authentication succeeds",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(
                                challengeResult.SessionId,
                                CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult));

                            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected authentication to succeed before validating share lookup.");

                            OpenCifsServerTreeConnectResult missingShareResult = host.HandleTreeConnect(
                                successResult.SessionId,
                                new Smb2TreeConnectRequest
                                {
                                    Path = "\\\\LAB-SERVER\\missing"
                                });
                            TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingShareResult.Status, "Expected the server to reject unknown shares.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerRejectsDuplicateExplicitShareRegistrations",
                        displayName: "Server builder rejects duplicate explicit filesystem share registrations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsDuplicateShares_" + Guid.NewGuid().ToString("N"));
                            string firstSharePath = Path.Combine(rootPath, "first");
                            string secondSharePath = Path.Combine(rootPath, "second");
                            Directory.CreateDirectory(firstSharePath);
                            Directory.CreateDirectory(secondSharePath);

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER"
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = firstSharePath,
                                    CreateRootIfMissing = true
                                });

                                try
                                {
                                    builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                    {
                                        ShareName = "PUBLIC",
                                        RootPath = secondSharePath,
                                        CreateRootIfMissing = true
                                    });
                                }
                                catch (OpenCifsServerConfigurationException)
                                {
                                    return Task.CompletedTask;
                                }

                                throw new InvalidOperationException("Expected duplicate share registration to be rejected.");
                            }
                            finally
                            {
                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.SessionTree",
                        caseId: "ServerAuthenticatesSessionsAndRejectsTreeConnectsThroughCallbacks",
                        displayName: "Server callback hooks authenticate sessions through the builder surface and reject selected tree connects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsCallbackSessions_" + Guid.NewGuid().ToString("N"));
                            string sharePath = Path.Combine(rootPath, "public");
                            string blockedSharePath = Path.Combine(rootPath, "blocked");
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(blockedSharePath);
                            int authenticatedCallbackCount = 0;
                            OpenCifsServerAuthenticatedSessionContext? authenticatedContext = null;
                            int treeConnectCallbackCount = 0;
                            OpenCifsServerTreeConnectContext? treeConnectContext = null;

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER"
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "blocked",
                                    RootPath = blockedSharePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });
                                builder.ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
                                {
                                    AuthenticatedSessionCallback = context =>
                                    {
                                        authenticatedCallbackCount++;
                                        authenticatedContext = context;
                                        return null;
                                    },
                                    TreeConnectCallback = context =>
                                    {
                                        treeConnectCallbackCount++;
                                        treeConnectContext = context;
                                        return string.Equals(context.ShareName, "blocked", StringComparison.OrdinalIgnoreCase)
                                            ? NtStatus.AccessDenied
                                            : null;
                                    }
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                ulong sessionId = AuthenticateSession(host);

                                TestAssertions.Equal(1, authenticatedCallbackCount, "Expected the authenticated-session callback to run exactly once.");
                                TestAssertions.True(authenticatedContext != null, "Expected the authenticated-session callback context to be captured.");
                                TestAssertions.Equal(sessionId, authenticatedContext!.SessionId, "Expected the callback to observe the assigned session identifier.");
                                TestAssertions.Equal("alice", authenticatedContext.UserName, "Expected the callback to observe the authenticated user name.");
                                TestAssertions.Equal("WORKGROUP", authenticatedContext.UserDomain, "Expected the callback to observe the authenticated user domain.");
                                TestAssertions.Equal("LegacyOpenCifs", authenticatedContext.AuthenticationFlavor, "Expected the shared authentication helper to use the current legacy OpenCIFS session-setup path.");

                                OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\blocked"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, treeConnectResult.Status, "Expected the tree-connect callback to reject the request.");
                                TestAssertions.Equal(1, treeConnectCallbackCount, "Expected the tree-connect callback to run exactly once.");
                                TestAssertions.True(treeConnectContext != null, "Expected the tree-connect callback context to be captured.");
                                TestAssertions.Equal(sessionId, treeConnectContext!.SessionId, "Expected the tree-connect callback to observe the authenticated session.");
                                TestAssertions.Equal("blocked", treeConnectContext.ShareName, "Expected the tree-connect callback to observe the resolved share name.");
                                TestAssertions.Equal(blockedSharePath, treeConnectContext.ShareRootPath, "Expected the tree-connect callback to observe the resolved share root.");
                                TestAssertions.Equal("\\\\LAB-SERVER\\blocked", treeConnectContext.Request.Path, "Expected the tree-connect callback to observe the requested UNC path.");

                                treeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected the allowed tree connect to succeed after the blocked-share rejection.");
                                TestAssertions.Equal(2, treeConnectCallbackCount, "Expected the tree-connect callback to run again for the allowed share.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> shareRootOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeConnectResult.TreeId,
                                    new Smb2CreateRequest
                                    {
                                        RequestedOplockLevel = Smb2OplockLevel.None,
                                        ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                        DesiredAccess = 0x80000080U,
                                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Directory,
                                        ShareAccess = 0x00000007U,
                                        CreateDisposition = Smb2CreateDisposition.Open,
                                        CreateOptions = Smb2CreateOptions.OpenReparsePoint,
                                        Name = string.Empty,
                                        CreateContexts = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, shareRootOpenResult.Status, "Expected empty-name share-root opens to succeed for the bounded Windows-compatible slice.");
                                TestAssertions.True((shareRootOpenResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0, "Expected empty-name share-root opens to resolve to a directory.");

                                TestAssertions.Throws<ProtocolValidationException>(
                                    () => host.HandleCreate(
                                        sessionId,
                                        treeConnectResult.TreeId,
                                        new Smb2CreateRequest
                                        {
                                            RequestedOplockLevel = Smb2OplockLevel.None,
                                            ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                            DesiredAccess = 0x80000080U,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                            ShareAccess = 0x00000007U,
                                            CreateDisposition = Smb2CreateDisposition.Open,
                                            CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                            Name = string.Empty,
                                            CreateContexts = Array.Empty<byte>()
                                        }),
                                    "Expected empty-name create requests that demand non-directory opens to remain rejected.");

                                OpenCifsServerHostBuilder rejectingBuilder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = "LAB-SERVER"
                                });
                                rejectingBuilder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = "public",
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                });
                                rejectingBuilder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = "alice",
                                    UserDomain = "WORKGROUP",
                                    Password = "Password123!"
                                });
                                rejectingBuilder.ConfigureRequestCallbacks(new OpenCifsServerRequestCallbacks
                                {
                                    AuthenticatedSessionCallback = _ => NtStatus.AccessDenied
                                });

                                OpenCifsServerHost rejectingHost = rejectingBuilder.BuildHost();
                                OpenCifsServerSessionSetupResult challengeResult = rejectingHost.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                                OpenCifsServerSessionSetupResult rejectedAuthenticationResult = rejectingHost.HandleSessionSetup(
                                    challengeResult.SessionId,
                                    CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult));
                                TestAssertions.Equal(NtStatus.AccessDenied, rejectedAuthenticationResult.Status, "Expected the authenticated-session callback to reject the completed session.");

                                OpenCifsServerTreeConnectResult rejectedTreeConnectResult = rejectingHost.HandleTreeConnect(
                                    challengeResult.SessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, rejectedTreeConnectResult.Status, "Expected rejected authenticated sessions to remain unusable for tree connect.");
                            }
                            finally
                            {
                                if (Directory.Exists(rootPath))
                                {
                                    Directory.Delete(rootPath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server SMB2 credit and header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerCreditHeaderSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Credits",
                displayName: "Server SMB2 credit and header handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerGrantsAndClampsCreditsWithinConfiguredWindow",
                        displayName: "Server grants SMB2 credits within the configured maximum and binds responses to accepted requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = "LAB-SERVER",
                                ShareName = "public",
                                SharePath = "SampleShare",
                                MaximumCredits = 4
                            });

                            TestAssertions.Equal(1, host.AvailableCredits, "Expected a new server host to start with one SMB2 credit.");

                            Smb2Header firstRequest = CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 4);
                            host.ValidateAndAcceptRequestHeader(firstRequest, Smb2Command.Negotiate);
                            TestAssertions.Equal(0, host.AvailableCredits, "Expected the accepted request to consume the only available server credit.");

                            Smb2Header firstResponse = host.CreateResponseHeader(firstRequest, NtStatus.Success);
                            TestAssertions.Equal((ushort)4, firstResponse.CreditRequest, "Expected the server to grant the requested credits up to the configured limit.");
                            TestAssertions.Equal(4, host.AvailableCredits, "Expected the server credit window to grow after the response header is created.");

                            Smb2Header secondRequest = CreateRequestHeader(Smb2Command.SessionSetup, messageId: 1, creditRequest: 4);
                            host.ValidateAndAcceptRequestHeader(secondRequest, Smb2Command.SessionSetup);
                            Smb2Header secondResponse = host.CreateResponseHeader(secondRequest, NtStatus.MoreProcessingRequired, sessionId: 9);
                            TestAssertions.Equal((ushort)1, secondResponse.CreditRequest, "Expected the server to clamp granted credits once the configured maximum has been reached.");
                            TestAssertions.Equal(4, host.AvailableCredits, "Expected the server to restore the configured maximum credit window after the response header is created.");
                            TestAssertions.Equal(9UL, secondResponse.SessionId, "Expected the server to propagate the assigned session identifier into the response header.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerRejectsInvalidRequestHeaders",
                        displayName: "Server tolerates compatible credit-charge values and rejects invalid SMB2 request flags and message identifiers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost nonZeroChargeHost = CreateServerHost();
                            nonZeroChargeHost.ValidateAndAcceptRequestHeader(
                                CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditCharge: 1),
                                Smb2Command.Negotiate);
                            TestAssertions.Equal(0, nonZeroChargeHost.AvailableCredits, "Expected the server to continue single-credit accounting while tolerating compatible request CreditCharge values.");

                            OpenCifsServerHost signedRequestHost = CreateServerHost();
                            signedRequestHost.ValidateAndAcceptRequestHeader(
                                CreateRequestHeader(Smb2Command.TreeConnect, messageId: 0, sessionId: 7, flags: Smb2HeaderFlags.Signed),
                                Smb2Command.TreeConnect,
                                expectedSessionId: 7);

                            OpenCifsServerHost badFlagsHost = CreateServerHost();
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => badFlagsHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, flags: Smb2HeaderFlags.ServerToRedir),
                                    Smb2Command.Negotiate),
                                "Expected the server to reject unsupported SMB2 request flags.");

                            OpenCifsServerHost badMessageIdHost = CreateServerHost();
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => badMessageIdHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 99),
                                    Smb2Command.Negotiate),
                                "Expected the server to reject request message identifiers outside the current credit window.");

                            OpenCifsServerHost reusedMessageIdHost = CreateServerHost();
                            Smb2Header acceptedRequest = CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 2);
                            reusedMessageIdHost.ValidateAndAcceptRequestHeader(acceptedRequest, Smb2Command.Negotiate);
                            reusedMessageIdHost.CreateResponseHeader(acceptedRequest, NtStatus.Success);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => reusedMessageIdHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Negotiate, messageId: 0),
                                    Smb2Command.Negotiate),
                                "Expected the server to reject reusing an SMB2 message identifier that has already been consumed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerTracksMultiCreditLargeIoHeaders",
                        displayName: "Server tracks bounded SMB 2.1 multi-credit read and write requests across credits and message-identifier ranges",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            Smb2Header negotiateHeader = CreateRequestHeader(Smb2Command.Negotiate, messageId: 0, creditRequest: 8);
                            host.ValidateAndAcceptRequestHeader(negotiateHeader, Smb2Command.Negotiate);
                            host.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb21 }
                            });
                            host.CreateResponseHeader(negotiateHeader, NtStatus.Success);
                            TestAssertions.Equal(8, host.AvailableCredits, "Expected the server credit window to grow before the multi-credit test request.");

                            Smb2Header largeReadHeader = CreateRequestHeader(Smb2Command.Read, messageId: 1, creditRequest: 4, creditCharge: 4, sessionId: 7, treeId: 42);
                            host.ValidateAndAcceptRequestHeader(largeReadHeader, Smb2Command.Read, expectedSessionId: 7, expectedTreeId: 42);
                            TestAssertions.Equal(4, host.AvailableCredits, "Expected the bounded large read request to consume four server credits.");
                            Smb2Header largeReadResponse = host.CreateResponseHeader(largeReadHeader, NtStatus.Success, sessionId: 7, treeId: 42);
                            TestAssertions.Equal((ushort)4, largeReadResponse.CreditRequest, "Expected the bounded large read response to return the requested four-credit window.");
                            TestAssertions.Equal(8, host.AvailableCredits, "Expected the bounded large read response to restore the server credit window.");

                            Smb2WriteRequest overchargedWriteRequest = new Smb2WriteRequest
                            {
                                Offset = 0,
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                Channel = 0,
                                RemainingBytes = 0,
                                Flags = Smb2WriteFlags.None,
                                DataBuffer = new byte[200000],
                                WriteChannelInfo = Array.Empty<byte>()
                            };
                            Smb2WriteRequestValidator.Validate(overchargedWriteRequest);
                            Smb2CompoundPacket overchargedWriteResponse = host.HandleCompoundRequestPacket(
                                new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Write, messageId: 5, creditRequest: 5, creditCharge: 5, sessionId: 7, treeId: 42),
                                        overchargedWriteRequest.ToByteArray())
                                }));
                            TestAssertions.Equal(1, overchargedWriteResponse.Entries.Count, "Expected the bounded overcharged large write packet to return a single SMB2 response entry.");
                            TestAssertions.Equal(NtStatus.AccessDenied, overchargedWriteResponse.Entries[0].Header.Status, "Expected the bounded overcharged large write packet to reach the write handler after credit validation.");
                            TestAssertions.Equal(8, host.AvailableCredits, "Expected the bounded overcharged large write response to restore the consumed server credits.");

                            host.ValidateAndAcceptRequestHeader(
                                CreateRequestHeader(Smb2Command.Echo, messageId: 10, sessionId: 7),
                                Smb2Command.Echo,
                                expectedSessionId: 7);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerRejectsInvalidLargeIoCreditShapes",
                        displayName: "Server rejects invalid bounded SMB 2.1 multi-credit large-I/O header and payload combinations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost legacyHost = CreateServerHost();
                            legacyHost.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb2002 }
                            });
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => legacyHost.ValidateAndAcceptRequestHeader(
                                    CreateRequestHeader(Smb2Command.Read, messageId: 0, creditCharge: 2, sessionId: 7, treeId: 42),
                                    Smb2Command.Read,
                                    expectedSessionId: 7,
                                    expectedTreeId: 42),
                                "Expected the server to reject multi-credit large-I/O headers before SMB 2.1 negotiation.");

                            OpenCifsServerHost underchargedHost = CreateServerHost();
                            underchargedHost.HandleNegotiate(new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new[] { SmbDialect.Smb21 }
                            });
                            Smb2WriteRequest underchargedWriteRequest = new Smb2WriteRequest
                            {
                                Offset = 0,
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                Channel = 0,
                                RemainingBytes = 0,
                                Flags = Smb2WriteFlags.None,
                                DataBuffer = new byte[200000],
                                WriteChannelInfo = Array.Empty<byte>()
                            };
                            Smb2WriteRequestValidator.Validate(underchargedWriteRequest);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => underchargedHost.HandleCompoundRequestPacket(
                                    new Smb2CompoundPacket(new[]
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Write, messageId: 0, creditCharge: 1, sessionId: 7, treeId: 42),
                                            underchargedWriteRequest.ToByteArray())
                                    })),
                                "Expected the server packet surface to reject large SMB2 write requests whose CreditCharge is smaller than the payload length requires.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerCancelsAcceptedPendingRequestsWithoutConsumingCredits",
                        displayName: "Server cancels accepted pending requests without consuming an additional credit and returns a cancelled target response",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            Smb2Header pendingHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, sessionId: sessionId);
                            host.ValidateAndAcceptRequestHeader(pendingHeader, Smb2Command.Echo, expectedSessionId: sessionId);
                            TestAssertions.Equal(0, host.AvailableCredits, "Expected the accepted pending request to consume the currently granted server credit.");

                            OpenCifsServerCancelResult cancelResult = host.HandleCancel(
                                new Smb2Header
                                {
                                    CreditCharge = 0,
                                    Status = NtStatus.Success,
                                    Command = Smb2Command.Cancel,
                                    CreditRequest = 0,
                                    Flags = Smb2HeaderFlags.None,
                                    NextCommand = 0,
                                    MessageId = pendingHeader.MessageId,
                                    SessionId = sessionId,
                                    Signature = new byte[16]
                                },
                                new Smb2CancelRequest());

                            TestAssertions.True(cancelResult.WasCancelled, "Expected the pending SMB2 echo request to be cancelled.");
                            TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected successful cancellation to emit a target response header.");
                            TestAssertions.Equal(Smb2Command.Echo, cancelResult.TargetResponseHeader!.Command, "Expected the cancelled target response to preserve the original command.");
                            TestAssertions.Equal(NtStatus.Cancelled, cancelResult.TargetResponseHeader.Status, "Expected successful cancellation to fail the target request with STATUS_CANCELLED.");
                            Smb2EchoResponse cancelledEchoResponse = Smb2EchoResponse.ReadFrom(cancelResult.TargetResponsePayload);
                            Smb2EchoResponseValidator.Validate(cancelledEchoResponse);
                            TestAssertions.Equal(3, host.AvailableCredits, "Expected the cancelled target response to restore the requested SMB2 credit window.");

                            OpenCifsServerCancelResult missingResult = host.HandleCancel(
                                new Smb2Header
                                {
                                    CreditCharge = 0,
                                    Status = NtStatus.Success,
                                    Command = Smb2Command.Cancel,
                                    CreditRequest = 0,
                                    Flags = Smb2HeaderFlags.None,
                                    NextCommand = 0,
                                    MessageId = pendingHeader.MessageId,
                                    SessionId = sessionId,
                                    Signature = new byte[16]
                                },
                                new Smb2CancelRequest());
                            TestAssertions.False(missingResult.WasCancelled, "Expected cancelling an already completed target request to become a no-op.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.CreateResponseHeader(pendingHeader, NtStatus.Success, sessionId: sessionId),
                                "Expected cancelled target requests to be removed from the pending-request table.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerValidatesSignedAuthenticatedPacketsAndAcceptsSignedCancel",
                        displayName: "Server validates signed authenticated SMB2 packets and accepts signed cancel requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            (ulong sessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(host);
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header echoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] echoBytes = CreateSignedPacketBytes(echoHeader, echoRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(echoBytes);

                            TestAssertions.True((parsedEchoPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected authenticated echo requests to carry the SMB2 Signed flag.");
                            host.ValidateRequestPacket(parsedEchoPacket, echoBytes);
                            host.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);

                            Smb2CancelRequest cancelRequest = new Smb2CancelRequest();
                            Smb2CancelRequestValidator.Validate(cancelRequest);
                            Smb2Header cancelHeader = CreateRequestHeader(Smb2Command.Cancel, messageId: echoHeader.MessageId, creditRequest: 1, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] cancelBytes = CreateSignedPacketBytes(cancelHeader, cancelRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket parsedCancelPacket = Smb2CompoundPacket.ReadFrom(cancelBytes);

                            TestAssertions.True((parsedCancelPacket.Entries[0].Header.Flags & Smb2HeaderFlags.Signed) != 0, "Expected signed sessions to sign SMB2 cancel headers.");
                            host.ValidateRequestPacket(parsedCancelPacket, cancelBytes);

                            OpenCifsServerCancelResult cancelResult = host.HandleCancel(
                                parsedCancelPacket.Entries[0].Header,
                                Smb2CancelRequest.ReadFrom(parsedCancelPacket.Entries[0].Payload));
                            TestAssertions.True(cancelResult.WasCancelled, "Expected the server to cancel the signed pending echo request.");
                            TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected signed cancel handling to emit the cancelled target response.");
                            TestAssertions.Equal(NtStatus.Cancelled, cancelResult.TargetResponseHeader!.Status, "Expected signed cancel handling to fail the target request with STATUS_CANCELLED.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleCancel(
                                    CreateRequestHeader(Smb2Command.Cancel, messageId: echoHeader.MessageId, creditRequest: 2, flags: Smb2HeaderFlags.Signed, sessionId: sessionId),
                                    new Smb2CancelRequest()),
                                "Expected cancel requests with CreditRequest values above 1 to remain rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerRejectsUnsignedOrTamperedSignedAuthenticatedPackets",
                        displayName: "Server rejects authenticated SMB2 packets that omit or violate required signatures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            (ulong sessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(host);
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header signedEchoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] signedEchoBytes = CreateSignedPacketBytes(signedEchoHeader, echoRequest.ToByteArray(), signingKey);
                            Smb2CompoundPacket parsedSignedEchoPacket = Smb2CompoundPacket.ReadFrom(signedEchoBytes);

                            Smb2Header unsignedEchoHeader = new Smb2Header
                            {
                                CreditCharge = parsedSignedEchoPacket.Entries[0].Header.CreditCharge,
                                Status = parsedSignedEchoPacket.Entries[0].Header.Status,
                                Command = parsedSignedEchoPacket.Entries[0].Header.Command,
                                CreditRequest = parsedSignedEchoPacket.Entries[0].Header.CreditRequest,
                                Flags = parsedSignedEchoPacket.Entries[0].Header.Flags & ~Smb2HeaderFlags.Signed,
                                NextCommand = parsedSignedEchoPacket.Entries[0].Header.NextCommand,
                                MessageId = parsedSignedEchoPacket.Entries[0].Header.MessageId,
                                ProcessId = parsedSignedEchoPacket.Entries[0].Header.ProcessId,
                                TreeId = parsedSignedEchoPacket.Entries[0].Header.TreeId,
                                AsyncId = parsedSignedEchoPacket.Entries[0].Header.AsyncId,
                                SessionId = parsedSignedEchoPacket.Entries[0].Header.SessionId,
                                Signature = new byte[16]
                            };
                            Smb2CompoundPacket unsignedEchoPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(unsignedEchoHeader, echoRequest.ToByteArray())
                                });
                            byte[] unsignedEchoBytes = unsignedEchoPacket.ToByteArray();
                            Smb2CompoundPacket parsedUnsignedEchoPacket = Smb2CompoundPacket.ReadFrom(unsignedEchoBytes);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedUnsignedEchoPacket, unsignedEchoBytes),
                                "Expected the server to reject authenticated SMB2 requests that omit the required Signed flag.");

                            byte[] tamperedEchoBytes = (byte[])signedEchoBytes.Clone();
                            tamperedEchoBytes[tamperedEchoBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedEchoPacket = Smb2CompoundPacket.ReadFrom(tamperedEchoBytes);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedTamperedEchoPacket, tamperedEchoBytes),
                                "Expected the server to reject authenticated SMB2 requests whose signatures no longer verify.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerUsesAesCmacForSignedPacketsWhenNegotiatedSmb302",
                        displayName: "Server validates and emits AES-CMAC SMB2 signatures when SMB 3.0.2 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            (ulong sessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(
                                host,
                                dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302 },
                                expectedDialect: SmbDialect.Smb302);
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header echoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] echoBytes = CreateSignedPacketBytes(echoHeader, echoRequest.ToByteArray(), signingKey, SmbDialect.Smb302);
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(echoBytes);

                            host.ValidateRequestPacket(parsedEchoPacket, echoBytes);
                            host.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);

                            byte[] tamperedEchoBytes = (byte[])echoBytes.Clone();
                            tamperedEchoBytes[tamperedEchoBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedEchoPacket = Smb2CompoundPacket.ReadFrom(tamperedEchoBytes);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedTamperedEchoPacket, tamperedEchoBytes),
                                "Expected the server to reject tampered AES-CMAC signed SMB2 requests.");

                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedEchoPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                            byte[] unsignedResponseBytes = (byte[])responseBytes.Clone();
                            Array.Clear(unsignedResponseBytes, 48, 16);
                            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            TestAssertions.True(
                                signer.Verify(unsignedResponseBytes, signingKey, ReadOnlySpan<byte>.Empty, parsedResponsePacket.Entries[0].Header.Signature),
                                "Expected the SMB 3.0.2 echo response signature to verify with AES-CMAC.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Credits",
                        caseId: "ServerUsesAesCmacForSignedPacketsWhenNegotiatedSmb30",
                        displayName: "Server validates and emits AES-CMAC SMB2 signatures when SMB 3.0 is negotiated",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost(requireEncryptionForSmb3: false);
                            (ulong sessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(
                                host,
                                dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30 },
                                expectedDialect: SmbDialect.Smb30);
                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            Smb2EchoRequestValidator.Validate(echoRequest);
                            Smb2Header echoHeader = CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 3, flags: Smb2HeaderFlags.Signed, sessionId: sessionId);
                            byte[] echoBytes = CreateSignedPacketBytes(echoHeader, echoRequest.ToByteArray(), signingKey, SmbDialect.Smb30);
                            Smb2CompoundPacket parsedEchoPacket = Smb2CompoundPacket.ReadFrom(echoBytes);

                            host.ValidateRequestPacket(parsedEchoPacket, echoBytes);
                            host.ValidateAndAcceptRequestHeader(parsedEchoPacket.Entries[0].Header, Smb2Command.Echo, expectedSessionId: sessionId);

                            byte[] tamperedEchoBytes = (byte[])echoBytes.Clone();
                            tamperedEchoBytes[tamperedEchoBytes.Length - 1] ^= 0x01;
                            Smb2CompoundPacket parsedTamperedEchoPacket = Smb2CompoundPacket.ReadFrom(tamperedEchoBytes);
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.ValidateRequestPacket(parsedTamperedEchoPacket, tamperedEchoBytes),
                                "Expected the server to reject tampered AES-CMAC signed SMB 3.0 requests.");

                            OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = host.HandleEcho(sessionId, echoRequest);
                            Smb2Header responseHeader = host.CreateResponseHeader(parsedEchoPacket.Entries[0].Header, echoResult.Status, sessionId: sessionId);
                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(responseHeader, echoResult.Response.ToByteArray())
                                });
                            byte[] responseBytes = host.FinalizeResponsePacket(responsePacket);
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                            byte[] unsignedResponseBytes = (byte[])responseBytes.Clone();
                            Array.Clear(unsignedResponseBytes, 48, 16);
                            IMessageSigner signer = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            TestAssertions.True(
                                signer.Verify(unsignedResponseBytes, signingKey, ReadOnlySpan<byte>.Empty, parsedResponsePacket.Entries[0].Header.Signature),
                                "Expected the SMB 3.0 echo response signature to verify with AES-CMAC.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server SMB2 CHANGE_NOTIFY suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerChangeNotifySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.ChangeNotify",
                displayName: "Server CHANGE_NOTIFY handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.ChangeNotify",
                        caseId: "ServerReturnsInterimPendingAndCancelsAsyncChangeNotifyRequests",
                        displayName: "Server returns interim async pending headers and cancels pending CHANGE_NOTIFY requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected opening the watched directory to succeed.");

                                Smb2Header notifyHeader = CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId);
                                OpenCifsServerAsyncResponse interimResponse = host.HandleChangeNotify(
                                    notifyHeader,
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });

                                TestAssertions.Equal(NtStatus.Pending, interimResponse.Header.Status, "Expected CHANGE_NOTIFY to enter async pending state.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand, interimResponse.Header.Flags, "Expected interim CHANGE_NOTIFY responses to carry the async flag.");
                                TestAssertions.Equal((ushort)3, interimResponse.Header.CreditRequest, "Expected the interim CHANGE_NOTIFY response to replenish the requested credits.");

                                OpenCifsServerCancelResult cancelResult = host.HandleCancel(
                                    CreateRequestHeader(
                                        Smb2Command.Cancel,
                                        messageId: notifyHeader.MessageId,
                                        creditRequest: 0,
                                        flags: Smb2HeaderFlags.AsyncCommand,
                                        sessionId: sessionId,
                                        asyncId: interimResponse.Header.AsyncId),
                                    new Smb2CancelRequest());

                                TestAssertions.True(cancelResult.WasCancelled, "Expected the pending CHANGE_NOTIFY request to be cancellable through the async cancel path.");
                                TestAssertions.True(cancelResult.TargetResponseHeader != null, "Expected async cancellation to emit a target response header.");
                                TestAssertions.Equal(NtStatus.Cancelled, cancelResult.TargetResponseHeader!.Status, "Expected async cancellation to fail the pending CHANGE_NOTIFY request with STATUS_CANCELLED.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand, cancelResult.TargetResponseHeader.Flags, "Expected the cancelled CHANGE_NOTIFY target response to remain async.");
                                TestAssertions.Equal((ushort)0, cancelResult.TargetResponseHeader.CreditRequest, "Expected final async CHANGE_NOTIFY cancellations to avoid granting credits a second time.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.ChangeNotify",
                        caseId: "ServerCompletesChangeNotifyRequestsForCreateAndOverflow",
                        displayName: "Server completes pending CHANGE_NOTIFY requests for create events and buffer overflow",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected opening the watched directory to succeed.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2CreateResponse> createChildResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("watched\\child.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.Success, createChildResult.Status, "Expected creating the child file to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? createdResponse) && createdResponse != null, "Expected the create event to complete the pending CHANGE_NOTIFY request.");
                                TestAssertions.Equal(NtStatus.Success, createdResponse!.Header.Status, "Expected the completed CHANGE_NOTIFY response to indicate success.");
                                FileNotifyInformation[] createdEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(createdResponse.Payload).OutputBuffer);
                                TestAssertions.Equal(1, createdEntries.Length, "Expected the create event to generate a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Added, createdEntries[0].Action, "Expected the created child file to surface as FILE_ACTION_ADDED.");
                                TestAssertions.Equal("child.txt", createdEntries[0].FileName, "Expected the created child file name to be relative to the watched directory.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = createChildResult.Response.PersistentFileId,
                                            VolatileFileId = createChildResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the created child file to close cleanly after the notify event.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 1, creditRequest: 1, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 4,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2CreateResponse> overflowCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("watched\\second-child.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.Success, overflowCreateResult.Status, "Expected the overflow child create to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? overflowResponse) && overflowResponse != null, "Expected the overflow create event to complete the pending CHANGE_NOTIFY request.");
                                TestAssertions.Equal(NtStatus.NotifyEnumDir, overflowResponse!.Header.Status, "Expected insufficient output buffers to surface as STATUS_NOTIFY_ENUM_DIR.");
                                TestAssertions.Equal(0, Smb2ChangeNotifyResponse.ReadFrom(overflowResponse.Payload).OutputBuffer.Length, "Expected STATUS_NOTIFY_ENUM_DIR responses to omit FILE_NOTIFY_INFORMATION entries.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = overflowCreateResult.Response.PersistentFileId,
                                            VolatileFileId = overflowCreateResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the overflow child file to close cleanly after the notify event.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = openResult.Response.PersistentFileId,
                                            VolatileFileId = openResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the watched directory open to close cleanly after the notify coverage.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.ChangeNotify",
                        caseId: "ServerCompletesChangeNotifyRequestsForRenameDeleteAndMetadataMutations",
                        displayName: "Server completes pending CHANGE_NOTIFY requests for same-directory rename, metadata mutation, and delete events",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerNotify_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "watched"));
                            File.WriteAllText(Path.Combine(sharePath, "watched", "sample.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, directoryOpenResult.Status, "Expected opening the watched directory to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "watched\\sample.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpenResult.Status, "Expected opening the watched file to succeed.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "watched\\renamed.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, renameResult.Status, "Expected the watched file rename to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? renameResponse) && renameResponse != null, "Expected the rename to complete the pending CHANGE_NOTIFY request.");
                                FileNotifyInformation[] renameEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(renameResponse!.Payload).OutputBuffer);
                                TestAssertions.Equal(2, renameEntries.Length, "Expected same-directory rename to surface old and new name notify entries.");
                                TestAssertions.Equal(FileNotifyAction.RenamedOldName, renameEntries[0].Action, "Expected the first rename notify entry to surface FILE_ACTION_RENAMED_OLD_NAME.");
                                TestAssertions.Equal("sample.txt", renameEntries[0].FileName, "Expected the first rename notify entry to preserve the original relative file name.");
                                TestAssertions.Equal(FileNotifyAction.RenamedNewName, renameEntries[1].Action, "Expected the second rename notify entry to surface FILE_ACTION_RENAMED_NEW_NAME.");
                                TestAssertions.Equal("renamed.txt", renameEntries[1].FileName, "Expected the second rename notify entry to preserve the renamed relative file name.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 1, creditRequest: 2, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.Attributes | FileNotifyChangeFilter.LastWrite
                                    });
                                ulong expectedLastWriteTime = 133595680890000000UL;
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> basicInfoResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            LastWriteTime = expectedLastWriteTime,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, basicInfoResult.Status, "Expected the watched file basic-info mutation to succeed.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? basicInfoResponse) && basicInfoResponse != null, "Expected the metadata mutation to complete the pending CHANGE_NOTIFY request.");
                                FileNotifyInformation[] basicInfoEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(basicInfoResponse!.Payload).OutputBuffer);
                                TestAssertions.Equal(1, basicInfoEntries.Length, "Expected the metadata mutation to surface a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Modified, basicInfoEntries[0].Action, "Expected the metadata mutation to surface FILE_ACTION_MODIFIED.");
                                TestAssertions.Equal("renamed.txt", basicInfoEntries[0].FileName, "Expected the metadata mutation to preserve the renamed relative file name.");

                                host.HandleChangeNotify(
                                    CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 2, creditRequest: 2, sessionId: sessionId, treeId: treeId),
                                    new Smb2ChangeNotifyRequest
                                    {
                                        Flags = Smb2ChangeNotifyFlags.None,
                                        OutputBufferLength = 256,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId,
                                        CompletionFilter = FileNotifyChangeFilter.FileName
                                    });
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionResult.Status, "Expected the watched file delete-pending mutation to succeed.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> deletedCloseResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        Flags = Smb2CloseFlags.None,
                                        PersistentFileId = fileOpenResult.Response.PersistentFileId,
                                        VolatileFileId = fileOpenResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, deletedCloseResult.Status, "Expected the delete-pending watched file to close cleanly.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? deleteResponse) && deleteResponse != null, "Expected the delete to complete the pending CHANGE_NOTIFY request.");
                                FileNotifyInformation[] deleteEntries = FileNotifyInformation.DecodeEntries(Smb2ChangeNotifyResponse.ReadFrom(deleteResponse!.Payload).OutputBuffer);
                                TestAssertions.Equal(1, deleteEntries.Length, "Expected the delete to surface a single notify entry.");
                                TestAssertions.Equal(FileNotifyAction.Removed, deleteEntries[0].Action, "Expected the delete to surface FILE_ACTION_REMOVED.");
                                TestAssertions.Equal("renamed.txt", deleteEntries[0].FileName, "Expected the delete to preserve the renamed relative file name.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        Flags = Smb2CloseFlags.None,
                                        PersistentFileId = directoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = directoryOpenResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryCloseResult.Status, "Expected the watched directory open to close cleanly after the extended notify coverage.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server echo suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerEchoSuite()
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

        /// <summary>
        /// Build the server SMB2 compounding suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerCompoundingSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Compounding",
                displayName: "Server SMB2 compounding handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerHandlesUnrelatedCompoundWriteFlushClosePacket",
                        displayName: "Server handles an unrelated compounded write, flush, and close packet against an authenticated open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("compound.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the server to open a backing file before compounded I/O.");

                                byte[] payload = Encoding.UTF8.GetBytes("compound data");
                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Write, messageId: 0, creditRequest: 3, sessionId: sessionId, treeId: treeId),
                                            new Smb2WriteRequest
                                            {
                                                Offset = 0,
                                                PersistentFileId = createResult.Response.PersistentFileId,
                                                VolatileFileId = createResult.Response.VolatileFileId,
                                                Channel = 0,
                                                RemainingBytes = 0,
                                                Flags = Smb2WriteFlags.None,
                                                DataBuffer = payload,
                                                WriteChannelInfo = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Flush, messageId: 1, sessionId: sessionId, treeId: treeId),
                                            new Smb2FlushRequest
                                            {
                                                PersistentFileId = createResult.Response.PersistentFileId,
                                                VolatileFileId = createResult.Response.VolatileFileId
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Close, messageId: 2, sessionId: sessionId, treeId: treeId),
                                            new Smb2CloseRequest
                                            {
                                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                                PersistentFileId = createResult.Response.PersistentFileId,
                                                VolatileFileId = createResult.Response.VolatileFileId
                                            }.ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(3, responsePacket.Entries.Count, "Unexpected compounded response entry count.");
                                TestAssertions.True(responsePacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded response to point at the next response entry.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the compounded write response to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected the compounded flush response to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[2].Header.Status, "Expected the compounded close response to succeed.");

                                Smb2WriteResponse writeResponse = Smb2WriteResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                                Smb2FlushResponse flushResponse = Smb2FlushResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[1].Header.Command, responsePacket.Entries[1].Payload));
                                Smb2CloseResponse closeResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[2].Header.Command, responsePacket.Entries[2].Payload));

                                Smb2FlushResponseValidator.Validate(flushResponse);
                                Smb2CloseResponseValidator.Validate(closeResponse);
                                TestAssertions.Equal((uint)payload.Length, writeResponse.Count, "Unexpected compounded write-response byte count.");
                                TestAssertions.Equal((ulong)payload.Length, closeResponse.EndOfFile, "Unexpected compounded close-response EOF size.");
                                TestAssertions.SequenceEqual(payload, File.ReadAllBytes(Path.Combine(sharePath, "compound.txt")), "Unexpected bytes persisted by the compounded server packet path.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerHandlesUnrelatedCompoundEchoAndLogoffPacket",
                        displayName: "Server handles an unrelated compounded echo and logoff packet against an authenticated session",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 2, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Logoff, messageId: 1, sessionId: sessionId),
                                        new Smb2LogoffRequest().ToByteArray())
                                });

                            Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                            TestAssertions.Equal(2, responsePacket.Entries.Count, "Unexpected compounded echo/logoff response entry count.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected compounded echo to succeed.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected compounded logoff to succeed.");

                            Smb2EchoResponse echoResponse = Smb2EchoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                            Smb2LogoffResponse logoffResponse = Smb2LogoffResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[1].Header.Command, responsePacket.Entries[1].Payload));
                            Smb2EchoResponseValidator.Validate(echoResponse);
                            Smb2LogoffResponseValidator.Validate(logoffResponse);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerCarriesSessionIdAcrossUnrelatedSessionSetupAndTreeConnectPacket",
                        displayName: "Server carries the authenticated session id across an unrelated compounded session-setup and tree-connect packet",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest("alice", "WORKGROUP"));
                            TestAssertions.Equal(NtStatus.MoreProcessingRequired, challengeResult.Status, "Expected the server to issue a session-setup challenge before compounded authentication.");

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.SessionSetup, messageId: 0, creditRequest: 2, sessionId: challengeResult.SessionId),
                                        CreateAuthenticateSessionSetupRequest("alice", "WORKGROUP", "Password123!", challengeResult).ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.TreeConnect, messageId: 1, sessionId: 0),
                                        new Smb2TreeConnectRequest
                                        {
                                            Path = "\\\\LAB-SERVER\\public"
                                        }.ToByteArray())
                                });

                            Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                            TestAssertions.Equal(2, responsePacket.Entries.Count, "Unexpected compounded session-setup/tree-connect response entry count.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the compounded session-setup completion to succeed.");
                            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected the compounded tree connect to succeed.");
                            TestAssertions.Equal(challengeResult.SessionId, responsePacket.Entries[1].Header.SessionId, "Expected the compounded tree-connect response to use the authenticated session id.");

                            Smb2SessionSetupResponse sessionSetupResponse = Smb2SessionSetupResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                            Smb2TreeConnectResponse treeConnectResponse = Smb2TreeConnectResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[1].Header.Command, responsePacket.Entries[1].Payload));
                            Smb2SessionSetupResponseValidator.Validate(sessionSetupResponse);
                            Smb2TreeConnectResponseValidator.Validate(treeConnectResponse);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerHandlesRelatedCompoundTreeConnectCreateMetadataLockIoctlCloseAndDisconnectPacket",
                        displayName: "Server handles a related compounded tree-connect, create, set-info, query-info, lock, IOCTL, close, and tree-disconnect packet",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerRelatedCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                ulong sessionId = AuthenticateSession(host);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.TreeConnect, messageId: 0, creditRequest: 9, sessionId: sessionId),
                                            new Smb2TreeConnectRequest
                                            {
                                                Path = "\\\\LAB-SERVER\\public"
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Create, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            CreateFileCreateRequest("related.txt", Smb2CreateDisposition.OpenIf).ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.SetInfo, messageId: 2, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.QueryInfo, messageId: 3, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Lock, messageId: 4, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Lock, messageId: 5, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.Unlock
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Ioctl, messageId: 6, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Close, messageId: 7, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2CloseRequest
                                            {
                                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.TreeDisconnect, messageId: 8, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2TreeDisconnectRequest().ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(9, responsePacket.Entries.Count, "Unexpected related compounded response entry count.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected related tree connect to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[1].Header.Status, "Expected related create to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[2].Header.Status, "Expected related set-info to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[3].Header.Status, "Expected related query-info to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[4].Header.Status, "Expected related lock to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[5].Header.Status, "Expected related unlock to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[6].Header.Status, "Expected related IOCTL to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[7].Header.Status, "Expected related close to succeed.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[8].Header.Status, "Expected related tree disconnect to succeed.");
                                TestAssertions.Equal(Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations, responsePacket.Entries[1].Header.Flags, "Expected subsequent related compounded responses to carry the related-operation flag.");

                                Smb2QueryInfoResponse queryInfoResponse = Smb2QueryInfoResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[3].Header.Command, responsePacket.Entries[3].Payload));
                                FileBasicInformation relatedBasicInformation = FileBasicInformation.ReadFrom(queryInfoResponse.OutputBuffer);
                                TestAssertions.True((relatedBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected related compounded FILE_BASIC_INFORMATION query results to include Hidden.");

                                Smb2IoctlResponse ioctlResponse = Smb2IoctlResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[6].Header.Command, responsePacket.Entries[6].Payload));
                                SrvSnapshotArray snapshotArray = SrvSnapshotArray.ReadFrom(ioctlResponse.OutputBuffer);
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected related compounded snapshot enumeration to return no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected related compounded snapshot enumeration to return an empty list.");
                                TestAssertions.True((File.GetAttributes(Path.Combine(sharePath, "related.txt")) & System.IO.FileAttributes.Hidden) != 0, "Expected the related compounded set-info request to persist the Hidden attribute.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerRejectsRelatedCompoundChainsWithoutRequiredContext",
                        displayName: "Server rejects related compounded packets that begin outside the supported synchronous compound surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);

                            Smb2CompoundPacket missingTreePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 0, creditRequest: 2, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Read, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                        new Smb2ReadRequest
                                        {
                                            Length = 1,
                                            Offset = 0,
                                            PersistentFileId = UInt64.MaxValue,
                                            VolatileFileId = UInt64.MaxValue,
                                            MinimumCount = 0,
                                            Channel = 0,
                                            RemainingBytes = 0,
                                            ReadChannelInfo = Array.Empty<byte>()
                                        }.ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(missingTreePacket.ToByteArray())),
                                "Expected related compounded packets that begin with commands outside the supported synchronous compound surface to be rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerPropagatesRelatedCreateFailureAcrossMetadataLockIoctlAndCloseOperations",
                        displayName: "Server propagates related compounded create failure statuses across later metadata, locking, IOCTL, and close operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerRelatedCompoundFailure_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "collision.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                ulong sessionId = AuthenticateSession(host);

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.TreeConnect, messageId: 0, creditRequest: 7, sessionId: sessionId),
                                            new Smb2TreeConnectRequest
                                            {
                                                Path = "\\\\LAB-SERVER\\public"
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Create, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            CreateFileCreateRequest("collision.txt", Smb2CreateDisposition.Create).ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.SetInfo, messageId: 2, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2SetInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Buffer = new FileBasicInformation
                                                {
                                                    FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                                }.ToByteArray()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.QueryInfo, messageId: 3, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2QueryInfoRequest
                                            {
                                                InfoType = Smb2InfoType.File,
                                                FileInfoClass = FileInformationClass.BasicInformation,
                                                OutputBufferLength = 512,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Lock, messageId: 4, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2LockRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                Locks = new[]
                                                {
                                                    new Smb2LockElement
                                                    {
                                                        Offset = 0,
                                                        Length = 4,
                                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                                    }
                                                }
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Ioctl, messageId: 5, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                                PersistentFileId = 1,
                                                VolatileFileId = 1,
                                                MaxInputResponse = 0,
                                                MaxOutputResponse = 512,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray()),
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Close, messageId: 6, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                            new Smb2CloseRequest
                                            {
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue
                                            }.ToByteArray())
                                    });

                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(7, responsePacket.Entries.Count, "Unexpected related compounded response count for the propagated-failure scenario.");
                                TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the leading tree connect to succeed.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[1].Header.Status, "Expected the related create to report the collision.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[2].Header.Status, "Expected the related set-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[3].Header.Status, "Expected the related query-info to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[4].Header.Status, "Expected the related lock to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[5].Header.Status, "Expected the related IOCTL to inherit the create failure status.");
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, responsePacket.Entries[6].Header.Status, "Expected the related close to inherit the create failure status.");
                                TestAssertions.Equal("seed", File.ReadAllText(Path.Combine(sharePath, "collision.txt")), "Expected propagated create failures to avoid mutating the backing file.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Compounding",
                        caseId: "ServerRejectsMixedCompoundStyles",
                        displayName: "Server rejects compounded request packets that mix unrelated and related operation styles",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHost host = CreateServerHost();
                            ulong sessionId = AuthenticateSession(host);
                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 0, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Logoff, messageId: 1, flags: Smb2HeaderFlags.RelatedOperations, sessionId: sessionId),
                                        new Smb2LogoffRequest().ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateRequestHeader(Smb2Command.Echo, messageId: 2, sessionId: sessionId),
                                        new Smb2EchoRequest().ToByteArray())
                                });

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => host.HandleCompoundRequestPacket(requestPacket),
                                "Expected the server to reject compounded packets that mix unrelated and related SMB2 operation styles.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server file-I/O suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerFileIoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.FileIo",
                displayName: "Server file-I/O handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerHandlesCreateWriteFlushReadAndClose",
                        displayName: "Server handles create, write, flush, read, and close against the configured share path",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                Smb2CreateRequest createRequest = CreateFileCreateRequest("notes.txt", Smb2CreateDisposition.OpenIf);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(sessionId, treeId, createRequest);

                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected file create to succeed.");
                                TestAssertions.True(createResult.Response.PersistentFileId != 0, "Expected the server to allocate a persistent file identifier.");

                                byte[] payload = Encoding.UTF8.GetBytes("hello file io");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 0,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = payload,
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, writeResult.Status, "Expected file write to succeed.");
                                TestAssertions.Equal((uint)payload.Length, writeResult.Response.Count, "Unexpected server write count.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = host.HandleFlush(
                                    sessionId,
                                    treeId,
                                    new Smb2FlushRequest
                                    {
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, flushResult.Status, "Expected file flush to succeed.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = (uint)payload.Length,
                                        Offset = 0,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        MinimumCount = (uint)payload.Length,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, readResult.Status, "Expected file read to succeed.");
                                TestAssertions.SequenceEqual(payload, readResult.Response.DataBuffer, "Unexpected bytes returned by the server read path.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        Flags = Smb2CloseFlags.PostQueryAttributes,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected file close to succeed.");
                                TestAssertions.Equal((ulong)payload.Length, closeResult.Response.EndOfFile, "Unexpected close-response EOF size.");

                                byte[] storedBytes = File.ReadAllBytes(Path.Combine(sharePath, "notes.txt"));
                                TestAssertions.SequenceEqual(payload, storedBytes, "Unexpected bytes persisted to the backing share path.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerToleratesSmb3CreateHintContextsOnFreshOpen",
                        displayName: "Server tolerates SMB 3.x durable and lease create hints on a fresh open without claiming the advanced features",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                                {
                                    ServerName = TestEnvironmentDefaults.DefaultServerName,
                                    MinimumDialect = SmbDialect.Smb302,
                                    MaximumDialect = SmbDialect.Smb302,
                                    RequireEncryptionForSmb3 = true
                                });
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
                                NegotiateDialect(host, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                Smb2CreateRequest createRequest = new Smb2CreateRequest
                                {
                                    RequestedOplockLevel = Smb2OplockLevel.None,
                                    ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                    DesiredAccess = 0x00100081U,
                                    FileAttributes = ProtocolFileAttributes.Directory,
                                    ShareAccess = 0x00000003U,
                                    CreateDisposition = Smb2CreateDisposition.Create,
                                    CreateOptions = Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.OpenReparsePoint,
                                    Name = "native-dir",
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2DurableHandleRequestV2Context
                                        {
                                            Timeout = 0,
                                            Flags = Smb2DurableHandleFlags.None,
                                            CreateGuid = Guid.NewGuid()
                                        }.ToCreateContext(),
                                        new Smb2CreateRequestLeaseContext
                                        {
                                            LeaseKey = new byte[16],
                                            LeaseState = Smb2LeaseState.ReadCaching
                                        }.ToCreateContext()
                                    })
                                };

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(sessionId, treeId, createRequest);

                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the server to tolerate bounded SMB 3.x create hints on a fresh open.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "native-dir")), "Expected the server to still materialize the requested directory.");
                                TestAssertions.Equal(0, createResult.Response.CreateContexts.Length, "Expected the bounded server path to tolerate but not advertise durable-handle v2 or lease-v2 response contexts.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerRejectsUnsupportedPathsAndStaleHandles",
                        displayName: "Server rejects create collisions, missing files, path traversal, and stale handles",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "existing.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> collisionResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("existing.txt", Smb2CreateDisposition.Create));
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, collisionResult.Status, "Expected create-new on an existing file to report a collision.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> missingOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("missing.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingOpenResult.Status, "Expected opening a missing file to fail.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> missingReadOnlyOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("missing-readonly.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingReadOnlyOpenResult.Status, "Expected read-only FILE_OPEN on a missing file to report STATUS_OBJECT_NAME_NOT_FOUND.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> traversalResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("..\\escape.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.ObjectPathNotFound, traversalResult.Status, "Expected path traversal outside the share root to be rejected.");

                                OpenCifsServerOperationResult<Smb2FlushResponse> staleHandleResult = host.HandleFlush(
                                    sessionId,
                                    treeId,
                                    new Smb2FlushRequest
                                    {
                                        PersistentFileId = 999,
                                        VolatileFileId = 999
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, staleHandleResult.Status, "Expected stale file identifiers to be rejected.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerRejectsInvalidSessionTreeAndOpenIdentifiersAcrossFileIoSurface",
                        displayName: "Server rejects invalid session, tree, and open identifiers across the bounded file-I/O surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerInvalidIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("identifiers.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected the invalid-identifier test open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateSessionResult = host.HandleCreate(
                                    sessionId + 1,
                                    treeId,
                                    CreateFileCreateRequest("other.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateSessionResult.Status, "Expected create requests with an unknown session identifier to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidCreateTreeResult = host.HandleCreate(
                                    sessionId,
                                    treeId + 1,
                                    CreateFileCreateRequest("other.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidCreateTreeResult.Status, "Expected create requests with an unknown tree identifier to be rejected.");

                                Smb2ReadRequest readRequest = new Smb2ReadRequest
                                {
                                    Length = 1,
                                    Offset = 0,
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId,
                                    MinimumCount = 0,
                                    Channel = 0,
                                    RemainingBytes = 0,
                                    ReadChannelInfo = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleRead(sessionId + 1, treeId, readRequest).Status, "Expected read requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleRead(sessionId, treeId + 1, readRequest).Status, "Expected read requests with an unknown tree identifier to be rejected.");

                                Smb2WriteRequest writeRequest = new Smb2WriteRequest
                                {
                                    Offset = 0,
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId,
                                    Channel = 0,
                                    RemainingBytes = 0,
                                    Flags = Smb2WriteFlags.None,
                                    DataBuffer = Encoding.UTF8.GetBytes("x"),
                                    WriteChannelInfo = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleWrite(sessionId + 1, treeId, writeRequest).Status, "Expected write requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleWrite(sessionId, treeId + 1, writeRequest).Status, "Expected write requests with an unknown tree identifier to be rejected.");

                                Smb2FlushRequest flushRequest = new Smb2FlushRequest
                                {
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleFlush(sessionId + 1, treeId, flushRequest).Status, "Expected flush requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleFlush(sessionId, treeId + 1, flushRequest).Status, "Expected flush requests with an unknown tree identifier to be rejected.");

                                Smb2LockRequest lockRequest = new Smb2LockRequest
                                {
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId,
                                    Locks = new[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 1,
                                            Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                        }
                                    }
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleLock(sessionId + 1, treeId, lockRequest).Status, "Expected lock requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleLock(sessionId, treeId + 1, lockRequest).Status, "Expected lock requests with an unknown tree identifier to be rejected.");

                                Smb2CloseRequest closeRequest = new Smb2CloseRequest
                                {
                                    PersistentFileId = createResult.Response.PersistentFileId,
                                    VolatileFileId = createResult.Response.VolatileFileId
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleClose(sessionId + 1, treeId, closeRequest).Status, "Expected close requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleClose(sessionId, treeId + 1, closeRequest).Status, "Expected close requests with an unknown tree identifier to be rejected.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> validCloseResult = host.HandleClose(sessionId, treeId, closeRequest);
                                TestAssertions.Equal(NtStatus.Success, validCloseResult.Status, "Expected the valid file-I/O test open to close cleanly.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerCreateCallbacksAllowSelectedPathsAndRejectBlockedCreates",
                        displayName: "Server create callbacks allow selected paths and reject blocked create requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsCreateCallbacks_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            int createCallbackCount = 0;
                            string? lastCreatePath = null;

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(
                                    sharePath,
                                    new OpenCifsServerRequestCallbacks
                                    {
                                        CreateCallback = context =>
                                        {
                                            createCallbackCount++;
                                            lastCreatePath = context.FullPath;

                                            if (context.Request.Name.StartsWith("blocked", StringComparison.OrdinalIgnoreCase))
                                            {
                                                return NtStatus.AccessDenied;
                                            }

                                            return null;
                                        }
                                    });

                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> allowedCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("allowed.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.Success, allowedCreateResult.Status, "Expected the create callback to allow selected create requests.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> allowedCloseResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = allowedCreateResult.Response.PersistentFileId,
                                        VolatileFileId = allowedCreateResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, allowedCloseResult.Status, "Expected the allowed create open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> blockedCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("blocked.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.AccessDenied, blockedCreateResult.Status, "Expected the create callback to reject blocked paths.");

                                TestAssertions.Equal(2, createCallbackCount, "Expected the create callback to run for both allowed and blocked requests.");
                                TestAssertions.Equal(Path.Combine(sharePath, "blocked.txt"), lastCreatePath, "Expected the create callback to observe the resolved blocked path.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "allowed.txt")), "Expected the allowed create path to reach the backing share.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "blocked.txt")), "Expected blocked create requests to leave no backing file.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerCreatesDirectoriesForCreateAndOpenIf",
                        displayName: "Server creates directories for bounded SMB2 directory create dispositions and reports collisions cleanly",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "existing-directory"));
                            File.WriteAllText(Path.Combine(sharePath, "existing-file.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "created-directory",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, createDirectoryResult.Status, "Expected FILE_CREATE on a missing directory path to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Created, createDirectoryResult.Response.CreateAction, "Expected FILE_CREATE on a missing directory path to report Created.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "created-directory")), "Expected the backing directory to be created.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> createDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = createDirectoryResult.Response.PersistentFileId,
                                        VolatileFileId = createDirectoryResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, createDirectoryClose.Status, "Expected the created-directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> openIfCreateDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "openif-directory",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, openIfCreateDirectoryResult.Status, "Expected FILE_OPEN_IF on a missing directory path to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Created, openIfCreateDirectoryResult.Response.CreateAction, "Expected FILE_OPEN_IF on a missing directory path to report Created.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "openif-directory")), "Expected FILE_OPEN_IF to create the missing backing directory.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> openIfCreateDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = openIfCreateDirectoryResult.Response.PersistentFileId,
                                        VolatileFileId = openIfCreateDirectoryResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, openIfCreateDirectoryClose.Status, "Expected the FILE_OPEN_IF-created directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> existingOpenIfDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, existingOpenIfDirectoryResult.Status, "Expected FILE_OPEN_IF on an existing directory to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Opened, existingOpenIfDirectoryResult.Response.CreateAction, "Expected FILE_OPEN_IF on an existing directory to report Opened.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> existingOpenIfDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = existingOpenIfDirectoryResult.Response.PersistentFileId,
                                        VolatileFileId = existingOpenIfDirectoryResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, existingOpenIfDirectoryClose.Status, "Expected the existing-directory FILE_OPEN_IF open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> plainExistingDirectoryOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x00000080U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.None,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, plainExistingDirectoryOpenResult.Status, "Expected Windows-style plain opens of existing directories to succeed when FILE_NON_DIRECTORY_FILE is not requested.");
                                TestAssertions.Equal(Smb2CreateAction.Opened, plainExistingDirectoryOpenResult.Response.CreateAction, "Expected plain opens of existing directories to report Opened.");
                                TestAssertions.True((plainExistingDirectoryOpenResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0, "Expected plain opens of existing directories to resolve to directory metadata.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> plainExistingDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = plainExistingDirectoryOpenResult.Response.PersistentFileId,
                                        VolatileFileId = plainExistingDirectoryOpenResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, plainExistingDirectoryClose.Status, "Expected the Windows-style plain directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> nonDirectoryExistingDirectoryOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x00000080U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Normal));
                                TestAssertions.Equal(NtStatus.FileIsADirectory, nonDirectoryExistingDirectoryOpenResult.Status, "Expected explicit FILE_NON_DIRECTORY_FILE opens against an existing directory to remain rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryCollisionResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-directory",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, directoryCollisionResult.Status, "Expected FILE_CREATE on an existing directory to report a collision.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileCollisionResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-file.txt",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.ObjectNameCollision, fileCollisionResult.Status, "Expected FILE_CREATE against an existing file through FILE_DIRECTORY_FILE to report a collision.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> notDirectoryResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-file.txt",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.NotADirectory, notDirectoryResult.Status, "Expected non-CREATE directory opens against an existing file to report STATUS_NOT_A_DIRECTORY.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerEnforcesShareModesAndDeletePendingLifecycle",
                        displayName: "Server enforces SMB2 share modes and delete-on-close pending behavior",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> sharedReadOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000001U));
                                TestAssertions.Equal(NtStatus.Success, sharedReadOpen.Status, "Expected the first read-only open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> writeConflict = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0x40000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.SharingViolation, writeConflict.Status, "Expected a write open to fail when the existing open does not share write access.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> shareConflict = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000000U));
                                TestAssertions.Equal(NtStatus.SharingViolation, shareConflict.Status, "Expected an open to fail when it does not share read access back to the existing reader.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> sharedClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = sharedReadOpen.Response.PersistentFileId,
                                        VolatileFileId = sharedReadOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, sharedClose.Status, "Expected the read-only share-mode open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> deleteOnCloseOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "delete-me.txt",
                                        Smb2CreateDisposition.OpenIf,
                                        desiredAccess: 0xC0010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseOpen.Status, "Expected delete-on-close create to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> deletePendingOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("delete-me.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.DeletePending, deletePendingOpen.Status, "Expected a new open against a delete-pending file to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> deleteOnCloseClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = deleteOnCloseOpen.Response.PersistentFileId,
                                        VolatileFileId = deleteOnCloseOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseClose.Status, "Expected delete-on-close open to close cleanly.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "delete-me.txt")), "Expected the delete-on-close file to be removed when the last open closes.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerHonorsSupersedeOverwriteAndOverwriteIf",
                        displayName: "Server honors bounded file supersede and overwrite create dispositions",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "overwrite.txt"), "seed overwrite");
                            File.WriteAllText(Path.Combine(sharePath, "supersede.txt"), "seed supersede");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> seededOverwriteOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("overwrite.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U));
                                TestAssertions.Equal(NtStatus.Success, seededOverwriteOpen.Status, "Expected the seed overwrite open to succeed.");
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seededOverwriteAllocation = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = seededOverwriteOpen.Response.PersistentFileId,
                                        VolatileFileId = seededOverwriteOpen.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 64
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededOverwriteAllocation.Status, "Expected the seed overwrite allocation update to succeed.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> seededOverwriteClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = seededOverwriteOpen.Response.PersistentFileId,
                                        VolatileFileId = seededOverwriteOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededOverwriteClose.Status, "Expected the seed overwrite open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("overwrite.txt", Smb2CreateDisposition.Overwrite, desiredAccess: 0x40000000U));
                                TestAssertions.Equal(NtStatus.Success, overwriteResult.Status, "Expected FILE_OVERWRITE on an existing file to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, overwriteResult.Response.CreateAction, "Expected FILE_OVERWRITE on an existing file to report Overwritten.");
                                TestAssertions.Equal(0UL, overwriteResult.Response.EndOfFile, "Expected FILE_OVERWRITE to truncate the existing file.");
                                TestAssertions.Equal(0UL, overwriteResult.Response.AllocationSize, "Expected FILE_OVERWRITE to reset declared allocation state after truncation.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> overwriteClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = overwriteResult.Response.PersistentFileId,
                                        VolatileFileId = overwriteResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, overwriteClose.Status, "Expected the overwritten file open to close cleanly.");
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "overwrite.txt")).Length, "Expected FILE_OVERWRITE to leave the backing file truncated.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> missingOverwriteResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("missing-overwrite.txt", Smb2CreateDisposition.Overwrite, desiredAccess: 0x40000000U));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingOverwriteResult.Status, "Expected FILE_OVERWRITE on a missing file to fail.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> overwriteIfMissingResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("overwrite-if-created.txt", Smb2CreateDisposition.OverwriteIf, desiredAccess: 0x40000000U));
                                TestAssertions.Equal(NtStatus.Success, overwriteIfMissingResult.Status, "Expected FILE_OVERWRITE_IF on a missing file to create the file.");
                                TestAssertions.Equal(Smb2CreateAction.Created, overwriteIfMissingResult.Response.CreateAction, "Expected FILE_OVERWRITE_IF on a missing file to report Created.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> overwriteIfMissingClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = overwriteIfMissingResult.Response.PersistentFileId,
                                        VolatileFileId = overwriteIfMissingResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, overwriteIfMissingClose.Status, "Expected the created overwrite-if file to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> seededSupersedeOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("supersede.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U));
                                TestAssertions.Equal(NtStatus.Success, seededSupersedeOpen.Status, "Expected the seed supersede open to succeed.");
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> seededSupersedeAllocation = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = seededSupersedeOpen.Response.PersistentFileId,
                                        VolatileFileId = seededSupersedeOpen.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 96
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededSupersedeAllocation.Status, "Expected the seed supersede allocation update to succeed.");
                                OpenCifsServerOperationResult<Smb2CloseResponse> seededSupersedeClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = seededSupersedeOpen.Response.PersistentFileId,
                                        VolatileFileId = seededSupersedeOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, seededSupersedeClose.Status, "Expected the seed supersede open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> supersedeResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("supersede.txt", Smb2CreateDisposition.Supersede, desiredAccess: 0xC0010000U));
                                TestAssertions.Equal(NtStatus.Success, supersedeResult.Status, "Expected FILE_SUPERSEDE on an existing file to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Superseded, supersedeResult.Response.CreateAction, "Expected FILE_SUPERSEDE on an existing file to report Superseded.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.EndOfFile, "Expected FILE_SUPERSEDE to replace the existing file with an empty file.");
                                TestAssertions.Equal(0UL, supersedeResult.Response.AllocationSize, "Expected FILE_SUPERSEDE to reset declared allocation state after replacement.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> supersedeClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = supersedeResult.Response.PersistentFileId,
                                        VolatileFileId = supersedeResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, supersedeClose.Status, "Expected the superseded file open to close cleanly.");
                                TestAssertions.Equal(0L, new FileInfo(Path.Combine(sharePath, "supersede.txt")).Length, "Expected FILE_SUPERSEDE to leave the backing file truncated.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerAppliesCreateTimeFileAttributesAndRejectsReadOnlyDeleteOnCloseCreates",
                        displayName: "Server applies bounded create-time file attributes and rejects read-only delete-on-close creates",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "overwrite-hidden.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenCreateResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "created-hidden.txt",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0xC0000000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                TestAssertions.Equal(NtStatus.Success, hiddenCreateResult.Status, "Expected hidden file create to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Created, hiddenCreateResult.Response.CreateAction, "Expected hidden file create to report Created.");
                                TestAssertions.True(
                                    (hiddenCreateResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected hidden file create to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "created-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected the backing file to receive the Hidden attribute on create.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenCreateClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = hiddenCreateResult.Response.PersistentFileId,
                                        VolatileFileId = hiddenCreateResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, hiddenCreateClose.Status, "Expected the hidden create open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> hiddenOverwriteResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "overwrite-hidden.txt",
                                        Smb2CreateDisposition.OverwriteIf,
                                        desiredAccess: 0xC0000000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Hidden));
                                TestAssertions.Equal(NtStatus.Success, hiddenOverwriteResult.Status, "Expected hidden overwrite-if to succeed.");
                                TestAssertions.Equal(Smb2CreateAction.Overwritten, hiddenOverwriteResult.Response.CreateAction, "Expected hidden overwrite-if on an existing file to report Overwritten.");
                                TestAssertions.True(
                                    (hiddenOverwriteResult.Response.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0,
                                    "Expected hidden overwrite-if to surface the Hidden attribute in the create response.");
                                TestAssertions.True(
                                    (new FileInfo(Path.Combine(sharePath, "overwrite-hidden.txt")).Attributes & System.IO.FileAttributes.Hidden) != 0,
                                    "Expected overwrite-if to apply the Hidden attribute to the backing file.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> hiddenOverwriteClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = hiddenOverwriteResult.Response.PersistentFileId,
                                        VolatileFileId = hiddenOverwriteResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, hiddenOverwriteClose.Status, "Expected the hidden overwrite-if open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDeleteOnCloseCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "transient-readonly.txt",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0xC0010000U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.ReadOnly));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDeleteOnCloseCreate.Status, "Expected read-only FILE_DELETE_ON_CLOSE on a new file to fail with STATUS_CANNOT_DELETE.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "transient-readonly.txt")), "Expected failed read-only delete-on-close create requests not to materialize a backing file.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerRejectsReadOnlyDeleteOnCloseForExistingAndDirectoryTargets",
                        displayName: "Server rejects read-only delete-on-close requests for existing files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-file.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        createOptions: Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyFileOpen.Status, "Expected existing read-only files to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the existing read-only file to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryOpen.Status, "Expected existing read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the existing read-only directory to remain after the failed delete-on-close open.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-created-directory",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80010000U,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory | OpenCIFS.Protocol.FileAttributes.ReadOnly));
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryCreate.Status, "Expected new read-only directories to reject FILE_DELETE_ON_CLOSE.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "readonly-created-directory")), "Expected failed read-only directory creates not to materialize a backing directory.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.FileIo",
                        caseId: "ServerDeletesEmptyDirectoriesAndRejectsNonEmptyDirectoryDeletePending",
                        displayName: "Server deletes empty directories on last close and rejects non-empty directory delete-pending requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "existing-empty"));
                            string existingNonEmptyPath = Path.Combine(sharePath, "existing-nonempty");
                            Directory.CreateDirectory(existingNonEmptyPath);
                            File.WriteAllText(Path.Combine(existingNonEmptyPath, "child.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> deleteOnCloseDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-empty",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseDirectoryOpen.Status, "Expected FILE_DELETE_ON_CLOSE on an existing empty directory to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> pendingChildCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("existing-empty\\child.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.DeletePending, pendingChildCreate.Status, "Expected child creates beneath a delete-pending directory to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> deleteOnCloseDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = deleteOnCloseDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = deleteOnCloseDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, deleteOnCloseDirectoryClose.Status, "Expected the delete-on-close directory open to close cleanly.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "existing-empty")), "Expected the empty delete-on-close directory to be removed on last close.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dispositionDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "disposition-empty",
                                        Smb2CreateDisposition.Create,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, dispositionDirectoryOpen.Status, "Expected creating a directory for FILE_DISPOSITION_INFORMATION coverage to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionSetResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = dispositionDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = dispositionDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionSetResult.Status, "Expected FILE_DISPOSITION_INFORMATION to allow delete-pending on an empty directory.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dispositionChildCreate = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("disposition-empty\\child.txt", Smb2CreateDisposition.OpenIf));
                                TestAssertions.Equal(NtStatus.DeletePending, dispositionChildCreate.Status, "Expected child creates beneath a disposition-marked directory to fail.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> dispositionDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = dispositionDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = dispositionDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionDirectoryClose.Status, "Expected the disposition-marked directory open to close cleanly.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "disposition-empty")), "Expected the disposition-marked empty directory to be removed on last close.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> nonEmptyDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "existing-nonempty",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, nonEmptyDirectoryOpen.Status, "Expected opening the non-empty directory to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> nonEmptyDispositionResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = nonEmptyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = nonEmptyDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.DirectoryNotEmpty, nonEmptyDispositionResult.Status, "Expected non-empty directories to reject delete-pending requests.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> nonEmptyDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = nonEmptyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = nonEmptyDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, nonEmptyDirectoryClose.Status, "Expected the non-empty directory open to close cleanly after the failed delete-pending request.");
                                TestAssertions.True(Directory.Exists(existingNonEmptyPath), "Expected the non-empty directory to remain after the failed delete-pending request.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server metadata suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerMetadataSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Metadata",
                displayName: "Server metadata handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerAllowsAttributeOnlyReopenWhileStillRejectingDataReadAcrossShareNone",
                        displayName: "Server allows attribute-only reopen across share-none while still rejecting data-read reopens",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "alpha.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> exclusiveOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("alpha.txt", Smb2CreateDisposition.Open, desiredAccess: 0x00120196U, shareAccess: 0x00000000U));
                                TestAssertions.Equal(NtStatus.Success, exclusiveOpenResult.Status, "Expected the initial share-none file open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("alpha.txt", Smb2CreateDisposition.Open, desiredAccess: 0x00000080U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyOpenResult.Status, "Expected metadata-only reopen requests to succeed across a share-none open.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> attributeOnlyInfoResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.InternalInformation,
                                        OutputBufferLength = 8,
                                        PersistentFileId = attributeOnlyOpenResult.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpenResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyInfoResult.Status, "Expected FILE_INTERNAL_INFORMATION on the metadata-only reopen to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dataReadOpenResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("alpha.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.SharingViolation, dataReadOpenResult.Status, "Expected data-read reopens to remain blocked across a share-none open.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = attributeOnlyOpenResult.Response.PersistentFileId,
                                            VolatileFileId = attributeOnlyOpenResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the metadata-only reopen to close cleanly.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        sessionId,
                                        treeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = exclusiveOpenResult.Response.PersistentFileId,
                                            VolatileFileId = exclusiveOpenResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the original share-none open to close cleanly.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerQueriesAndMutatesMetadataOnTrackedOpen",
                        displayName: "Server handles bounded query-info and set-info metadata operations on a tracked open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "archive"));
                            File.WriteAllText(Path.Combine(sharePath, "alpha.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("alpha.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> nameResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.NameInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, nameResult.Status, "Expected FILE_NAME_INFORMATION query to succeed.");
                                FileNameInformation initialName = FileNameInformation.ReadFrom(nameResult.Response.OutputBuffer);
                                TestAssertions.Equal("alpha.txt", initialName.FileName, "Unexpected initial FILE_NAME_INFORMATION path.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> allocationResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 64
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, allocationResult.Status, "Expected FILE_ALLOCATION_INFORMATION to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> endOfFileResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.EndOfFileInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileEndOfFileInformation
                                        {
                                            EndOfFile = 12
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, endOfFileResult.Status, "Expected FILE_END_OF_FILE_INFORMATION to succeed.");

                                ulong creationTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 4, DateTimeKind.Utc).ToFileTimeUtc());
                                ulong lastAccessTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 5, DateTimeKind.Utc).ToFileTimeUtc());
                                ulong lastWriteTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 6, DateTimeKind.Utc).ToFileTimeUtc());
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> basicResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            CreationTime = creationTime,
                                            LastAccessTime = lastAccessTime,
                                            LastWriteTime = lastWriteTime,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, basicResult.Status, "Expected FILE_BASIC_INFORMATION to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> standardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, standardResult.Status, "Expected FILE_STANDARD_INFORMATION query to succeed.");
                                FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(standardResult.Response.OutputBuffer);
                                TestAssertions.Equal(64UL, standardInformation.AllocationSize, "Unexpected FILE_STANDARD_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, standardInformation.EndOfFile, "Unexpected FILE_STANDARD_INFORMATION EOF size.");
                                TestAssertions.False(standardInformation.DeletePending, "The open should not be delete-pending before FILE_DISPOSITION_INFORMATION runs.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> basicQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, basicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query to succeed.");
                                FileBasicInformation queriedBasicInformation = FileBasicInformation.ReadFrom(basicQueryResult.Response.OutputBuffer);
                                TestAssertions.Equal(creationTime, queriedBasicInformation.CreationTime, "Unexpected FILE_BASIC_INFORMATION creation time after update.");
                                TestAssertions.Equal(lastAccessTime, queriedBasicInformation.LastAccessTime, "Unexpected FILE_BASIC_INFORMATION last-access time after update.");
                                TestAssertions.Equal(lastWriteTime, queriedBasicInformation.LastWriteTime, "Unexpected FILE_BASIC_INFORMATION last-write time after update.");
                                TestAssertions.True((queriedBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected FILE_BASIC_INFORMATION attributes to include Hidden.");

                                ulong changeTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 7, DateTimeKind.Utc).ToFileTimeUtc());
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> changeTimeResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            ChangeTime = changeTime
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, changeTimeResult.Status, "Expected ChangeTime-only FILE_BASIC_INFORMATION updates to succeed in the current slice.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> changedBasicQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, changedBasicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query after a ChangeTime-only update to succeed.");
                                FileBasicInformation changedBasicInformation = FileBasicInformation.ReadFrom(changedBasicQueryResult.Response.OutputBuffer);
                                TestAssertions.Equal(lastWriteTime, changedBasicInformation.LastWriteTime, "Expected explicit ChangeTime updates to preserve FILE_BASIC_INFORMATION last-write time.");
                                TestAssertions.Equal(changeTime, changedBasicInformation.ChangeTime, "Expected FILE_BASIC_INFORMATION queries to reflect the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> networkOpenResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.NetworkOpenInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, networkOpenResult.Status, "Expected FILE_NETWORK_OPEN_INFORMATION query to succeed.");
                                FileNetworkOpenInformation networkOpenInformation = FileNetworkOpenInformation.ReadFrom(networkOpenResult.Response.OutputBuffer);
                                TestAssertions.Equal(64UL, networkOpenInformation.AllocationSize, "Unexpected FILE_NETWORK_OPEN_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, networkOpenInformation.EndOfFile, "Unexpected FILE_NETWORK_OPEN_INFORMATION EOF size.");
                                TestAssertions.True((networkOpenInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected FILE_NETWORK_OPEN_INFORMATION attributes to include Hidden.");
                                TestAssertions.Equal(changeTime, networkOpenInformation.ChangeTime, "Expected FILE_NETWORK_OPEN_INFORMATION change time to reflect the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> internalInformationResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.InternalInformation,
                                        OutputBufferLength = 8,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, internalInformationResult.Status, "Expected FILE_INTERNAL_INFORMATION query to succeed.");
                                FileInternalInformation internalInformation = FileInternalInformation.ReadFrom(internalInformationResult.Response.OutputBuffer);
                                TestAssertions.Equal(createResult.Response.PersistentFileId, internalInformation.IndexNumber, "Expected FILE_INTERNAL_INFORMATION to return the stable open index number.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> allInformationResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, allInformationResult.Status, "Expected FILE_ALL_INFORMATION query to succeed.");
                                FileAllInformation allInformation = FileAllInformation.ReadFrom(allInformationResult.Response.OutputBuffer);
                                TestAssertions.Equal("alpha.txt", allInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name payload.");
                                TestAssertions.Equal(64UL, allInformation.StandardInformation.AllocationSize, "Unexpected FILE_ALL_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, allInformation.StandardInformation.EndOfFile, "Unexpected FILE_ALL_INFORMATION EOF size.");
                                TestAssertions.Equal(changeTime, allInformation.BasicInformation.ChangeTime, "Expected FILE_ALL_INFORMATION change time to reflect the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSizeResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileSystemSizeResult.Status, "Expected FILE_FS_SIZE_INFORMATION query to succeed.");
                                FileFsSizeInformation fileSystemSizeInformation = FileFsSizeInformation.ReadFrom(fileSystemSizeResult.Response.OutputBuffer);
                                TestAssertions.True(fileSystemSizeInformation.TotalAllocationUnits >= fileSystemSizeInformation.AvailableAllocationUnits, "Expected FILE_FS_SIZE_INFORMATION total allocation units to be at least the available count.");
                                TestAssertions.True(fileSystemSizeInformation.SectorsPerAllocationUnit > 0, "Expected FILE_FS_SIZE_INFORMATION sectors per allocation unit to be positive.");
                                TestAssertions.True(fileSystemSizeInformation.BytesPerSector > 0, "Expected FILE_FS_SIZE_INFORMATION bytes per sector to be positive.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemVolumeResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.VolumeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileSystemVolumeResult.Status, "Expected FILE_FS_VOLUME_INFORMATION query to succeed.");
                                FileFsVolumeInformation fileSystemVolumeInformation = FileFsVolumeInformation.ReadFrom(fileSystemVolumeResult.Response.OutputBuffer);
                                TestAssertions.True(fileSystemVolumeInformation.VolumeSerialNumber != 0, "Expected FILE_FS_VOLUME_INFORMATION serial numbers to be populated.");
                                TestAssertions.True(fileSystemVolumeInformation.VolumeLabel.Length != 0, "Expected FILE_FS_VOLUME_INFORMATION labels to be non-empty.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemAttributeResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.AttributeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileSystemAttributeResult.Status, "Expected FILE_FS_ATTRIBUTE_INFORMATION query to succeed.");
                                FileFsAttributeInformation fileSystemAttributeInformation = FileFsAttributeInformation.ReadFrom(fileSystemAttributeResult.Response.OutputBuffer);
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.CasePreservedNames) != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION to preserve filename casing.");
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.UnicodeOnDisk) != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION to advertise Unicode support.");
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.PersistentAcls) != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION to advertise persistent ACL support.");
                                TestAssertions.True(fileSystemAttributeInformation.MaximumComponentNameLength > 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION maximum component lengths to be positive.");
                                TestAssertions.True(fileSystemAttributeInformation.FileSystemName.Length != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION filesystem names to be non-empty.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemDeviceResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.DeviceInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileSystemDeviceResult.Status, "Expected FILE_FS_DEVICE_INFORMATION query to succeed.");
                                FileFsDeviceInformation fileSystemDeviceInformation = FileFsDeviceInformation.ReadFrom(fileSystemDeviceResult.Response.OutputBuffer);
                                TestAssertions.Equal(FileSystemDeviceType.Disk, fileSystemDeviceInformation.DeviceType, "Expected FILE_FS_DEVICE_INFORMATION to identify a disk-backed share.");
                                TestAssertions.True((fileSystemDeviceInformation.Characteristics & FileSystemDeviceCharacteristics.RemoteDevice) != 0, "Expected FILE_FS_DEVICE_INFORMATION to advertise a remote device.");
                                TestAssertions.True((fileSystemDeviceInformation.Characteristics & FileSystemDeviceCharacteristics.DeviceIsMounted) != 0, "Expected FILE_FS_DEVICE_INFORMATION to advertise a mounted device.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemFullSizeResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.FullSizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileSystemFullSizeResult.Status, "Expected FILE_FS_FULL_SIZE_INFORMATION query to succeed.");
                                FileFsFullSizeInformation fileSystemFullSizeInformation = FileFsFullSizeInformation.ReadFrom(fileSystemFullSizeResult.Response.OutputBuffer);
                                TestAssertions.True(fileSystemFullSizeInformation.TotalAllocationUnits >= fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected FILE_FS_FULL_SIZE_INFORMATION total allocation units to be at least the available count.");
                                TestAssertions.Equal(fileSystemFullSizeInformation.CallerAvailableAllocationUnits, fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected FILE_FS_FULL_SIZE_INFORMATION caller and actual availability to match for the bounded slice.");
                                TestAssertions.True(fileSystemFullSizeInformation.BytesPerSector > 0, "Expected FILE_FS_FULL_SIZE_INFORMATION bytes per sector to be positive.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSectorSizeResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SectorSizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileSystemSectorSizeResult.Status, "Expected FILE_FS_SECTOR_SIZE_INFORMATION query to succeed.");
                                FileFsSectorSizeInformation fileSystemSectorSizeInformation = FileFsSectorSizeInformation.ReadFrom(fileSystemSectorSizeResult.Response.OutputBuffer);
                                TestAssertions.True(fileSystemSectorSizeInformation.LogicalBytesPerSector > 0, "Expected FILE_FS_SECTOR_SIZE_INFORMATION logical bytes per sector to be positive.");
                                TestAssertions.True(fileSystemSectorSizeInformation.PhysicalBytesPerSectorForAtomicity >= fileSystemSectorSizeInformation.LogicalBytesPerSector, "Expected FILE_FS_SECTOR_SIZE_INFORMATION atomicity bytes per sector to be at least the logical size.");
                                TestAssertions.True((fileSystemSectorSizeInformation.Flags & FileSystemSectorSizeFlags.AlignedDevice) != 0, "Expected FILE_FS_SECTOR_SIZE_INFORMATION to advertise aligned devices.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyDisableResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue,
                                            LastAccessTime = UInt64.MaxValue,
                                            LastWriteTime = UInt64.MaxValue,
                                            ChangeTime = UInt64.MaxValue
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, stickyDisableResult.Status, "Expected sticky FILE_BASIC_INFORMATION disable directives to succeed.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> suppressedReadResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = 1,
                                        Offset = 0,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        MinimumCount = 1,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, suppressedReadResult.Status, "Expected reads to succeed while timestamp updates are disabled.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> suppressedWriteResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 0,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = new byte[] { 0x41 },
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, suppressedWriteResult.Status, "Expected writes to succeed while timestamp updates are disabled.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> suppressedAllocationResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 96
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, suppressedAllocationResult.Status, "Expected FILE_ALLOCATION_INFORMATION to succeed while timestamp updates are disabled.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> suppressedEndOfFileResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.EndOfFileInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileEndOfFileInformation
                                        {
                                            EndOfFile = 16
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, suppressedEndOfFileResult.Status, "Expected FILE_END_OF_FILE_INFORMATION to succeed while timestamp updates are disabled.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> suppressedStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, suppressedStandardResult.Status, "Expected FILE_STANDARD_INFORMATION query after disabled timestamp updates to succeed.");
                                FileStandardInformation suppressedStandardInformation = FileStandardInformation.ReadFrom(suppressedStandardResult.Response.OutputBuffer);
                                TestAssertions.Equal(96UL, suppressedStandardInformation.AllocationSize, "Expected allocation updates to remain visible while timestamps are pinned.");
                                TestAssertions.Equal(16UL, suppressedStandardInformation.EndOfFile, "Expected EOF updates to remain visible while timestamps are pinned.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> suppressedBasicQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, suppressedBasicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query after disabled timestamp updates to succeed.");
                                FileBasicInformation suppressedBasicInformation = FileBasicInformation.ReadFrom(suppressedBasicQueryResult.Response.OutputBuffer);
                                TestAssertions.Equal(creationTime, suppressedBasicInformation.CreationTime, "Expected sticky FILE_BASIC_INFORMATION directives to preserve creation time.");
                                TestAssertions.Equal(lastAccessTime, suppressedBasicInformation.LastAccessTime, "Expected reads through a sticky-disabled handle to preserve last-access time.");
                                TestAssertions.Equal(lastWriteTime, suppressedBasicInformation.LastWriteTime, "Expected writes through a sticky-disabled handle to preserve last-write time.");
                                TestAssertions.Equal(changeTime, suppressedBasicInformation.ChangeTime, "Expected metadata mutations through a sticky-disabled handle to preserve change time.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyEnableResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue - 1,
                                            LastAccessTime = UInt64.MaxValue - 1,
                                            LastWriteTime = UInt64.MaxValue - 1,
                                            ChangeTime = UInt64.MaxValue - 1
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, stickyEnableResult.Status, "Expected sticky FILE_BASIC_INFORMATION enable directives to succeed.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> resumedReadResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = 1,
                                        Offset = 0,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        MinimumCount = 1,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, resumedReadResult.Status, "Expected reads to succeed after re-enabling automatic timestamp updates.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> resumedWriteResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 1,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = new byte[] { 0x42 },
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, resumedWriteResult.Status, "Expected writes to succeed after re-enabling automatic timestamp updates.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedBasicQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, resumedBasicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query after re-enabled timestamp updates to succeed.");
                                FileBasicInformation resumedBasicInformation = FileBasicInformation.ReadFrom(resumedBasicQueryResult.Response.OutputBuffer);
                                TestAssertions.Equal(creationTime, resumedBasicInformation.CreationTime, "Expected automatic timestamp updates to leave creation time unchanged.");
                                TestAssertions.True(resumedBasicInformation.LastAccessTime != lastAccessTime, "Expected reads after sticky re-enable to advance last-access time.");
                                TestAssertions.True(resumedBasicInformation.LastWriteTime != lastWriteTime, "Expected writes after sticky re-enable to advance last-write time.");
                                TestAssertions.True(resumedBasicInformation.ChangeTime != changeTime, "Expected metadata mutations after sticky re-enable to advance change time.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedNetworkOpenResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.NetworkOpenInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, resumedNetworkOpenResult.Status, "Expected FILE_NETWORK_OPEN_INFORMATION query after re-enabled timestamp updates to succeed.");
                                FileNetworkOpenInformation resumedNetworkOpenInformation = FileNetworkOpenInformation.ReadFrom(resumedNetworkOpenResult.Response.OutputBuffer);
                                TestAssertions.Equal(resumedBasicInformation.LastWriteTime, resumedNetworkOpenInformation.LastWriteTime, "Expected FILE_NETWORK_OPEN_INFORMATION last-write time to match FILE_BASIC_INFORMATION after automatic updates resume.");
                                TestAssertions.Equal(resumedBasicInformation.ChangeTime, resumedNetworkOpenInformation.ChangeTime, "Expected FILE_NETWORK_OPEN_INFORMATION change time to match FILE_BASIC_INFORMATION after automatic updates resume.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "archive\\beta.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, renameResult.Status, "Expected FILE_RENAME_INFORMATION_TYPE_2 to succeed.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "alpha.txt")), "Expected the original file path to be removed after rename.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "archive", "beta.txt")), "Expected the renamed file path to exist after rename.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> renamedNameResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.NameInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, renamedNameResult.Status, "Expected FILE_NAME_INFORMATION query after rename to succeed.");
                                FileNameInformation renamedName = FileNameInformation.ReadFrom(renamedNameResult.Response.OutputBuffer);
                                TestAssertions.Equal("archive\\beta.txt", renamedName.FileName, "Unexpected FILE_NAME_INFORMATION path after rename.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, dispositionResult.Status, "Expected FILE_DISPOSITION_INFORMATION to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> deletePendingResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, deletePendingResult.Status, "Expected FILE_STANDARD_INFORMATION query after disposition to succeed.");
                                FileStandardInformation deletePendingInformation = FileStandardInformation.ReadFrom(deletePendingResult.Response.OutputBuffer);
                                TestAssertions.True(deletePendingInformation.DeletePending, "Expected FILE_DISPOSITION_INFORMATION to mark the open delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = createResult.Response.PersistentFileId,
                                        VolatileFileId = createResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected metadata test close to succeed.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "archive", "beta.txt")), "Expected the delete-pending renamed file to be removed on last close.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRejectsDispositionDeletePendingOnReadOnlyFilesAndDirectories",
                        displayName: "Server rejects FILE_DISPOSITION_INFORMATION delete-pending on read-only files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("readonly-file.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, readOnlyFileOpen.Status, "Expected opening the read-only file for disposition coverage to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyFileDisposition = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = readOnlyFileOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyFileOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyFileDisposition.Status, "Expected read-only files to reject FILE_DISPOSITION_INFORMATION delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyFileStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = readOnlyFileOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyFileOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyFileStandardResult.Status, "Expected FILE_STANDARD_INFORMATION query on the read-only file to succeed after the failed delete-pending request.");
                                FileStandardInformation readOnlyFileStandard = FileStandardInformation.ReadFrom(readOnlyFileStandardResult.Response.OutputBuffer);
                                TestAssertions.False(readOnlyFileStandard.DeletePending, "Expected failed read-only file disposition requests not to mark the file delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyFileClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = readOnlyFileOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyFileOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyFileClose.Status, "Expected the read-only file open to close cleanly after the failed delete-pending request.");
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the read-only file to remain after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, readOnlyDirectoryOpen.Status, "Expected opening the read-only directory for disposition coverage to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyDirectoryDisposition = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = readOnlyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryDisposition.Status, "Expected read-only directories to reject FILE_DISPOSITION_INFORMATION delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyDirectoryStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = readOnlyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyDirectoryOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyDirectoryStandardResult.Status, "Expected FILE_STANDARD_INFORMATION query on the read-only directory to succeed after the failed delete-pending request.");
                                FileStandardInformation readOnlyDirectoryStandard = FileStandardInformation.ReadFrom(readOnlyDirectoryStandardResult.Response.OutputBuffer);
                                TestAssertions.False(readOnlyDirectoryStandard.DeletePending, "Expected failed read-only directory disposition requests not to mark the directory delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = readOnlyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyDirectoryClose.Status, "Expected the read-only directory open to close cleanly after the failed delete-pending request.");
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the read-only directory to remain after the failed disposition request.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerMetadataCallbacksAllowTrackedOpensAndRejectSetInfoAndQueryDirectoryRequests",
                        displayName: "Server metadata callbacks allow tracked opens and reject selected set-info and query-directory requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsMetadataCallbacks_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "query.txt"), "seed");
                            int queryDirectoryCallbackCount = 0;
                            int setInfoCallbackCount = 0;

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(
                                    sharePath,
                                    new OpenCifsServerRequestCallbacks
                                    {
                                        QueryDirectoryCallback = context =>
                                        {
                                            queryDirectoryCallbackCount++;
                                            TestAssertions.Equal("public", context.ShareName, "Expected the query-directory callback to observe the resolved share name.");
                                            TestAssertions.Equal(Path.Combine(sharePath, "folder"), context.FullPath, "Expected the query-directory callback to observe the resolved directory path.");
                                            return NtStatus.AccessDenied;
                                        },
                                        SetInfoCallback = context =>
                                        {
                                            setInfoCallbackCount++;
                                            TestAssertions.Equal("public", context.ShareName, "Expected the set-info callback to observe the resolved share name.");
                                            TestAssertions.Equal(Path.Combine(sharePath, "query.txt"), context.FullPath, "Expected the set-info callback to observe the resolved file path.");

                                            if (context.Request.FileInfoClass == FileInformationClass.RenameInformation)
                                            {
                                                return NtStatus.NotSupported;
                                            }

                                            return null;
                                        }
                                    });

                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the directory open to succeed before query-directory callback enforcement.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> queryDirectoryResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, queryDirectoryResult.Status, "Expected the query-directory callback to reject directory enumeration.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryClose.Status, "Expected the callback-protected directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("query.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpen.Status, "Expected the file open to succeed before set-info callback enforcement.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "renamed.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, renameResult.Status, "Expected the set-info callback to reject the selected rename mutation.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> fileClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, fileClose.Status, "Expected the callback-protected file open to close cleanly.");

                                TestAssertions.Equal(1, queryDirectoryCallbackCount, "Expected the query-directory callback to run once.");
                                TestAssertions.Equal(1, setInfoCallbackCount, "Expected the set-info callback to run once for the selected rename request.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "query.txt")), "Expected the rejected rename to leave the original file in place.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "renamed.txt")), "Expected the rejected rename to avoid creating a renamed destination.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerEnumeratesDirectoryEntriesOnTrackedDirectoryOpen",
                        displayName: "Server handles bounded query-directory enumeration on a tracked directory open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder", "nested"));
                            File.WriteAllText(Path.Combine(sharePath, "folder", "alpha.txt"), "alpha");
                            File.WriteAllText(Path.Combine(sharePath, "folder", "beta.log"), "beta");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the directory metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> standardInfoResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, standardInfoResult.Status, "Expected FILE_STANDARD_INFORMATION on a directory open to succeed.");
                                FileStandardInformation directoryStandardInformation = FileStandardInformation.ReadFrom(standardInfoResult.Response.OutputBuffer);
                                TestAssertions.True(directoryStandardInformation.Directory, "Expected the directory open to report Directory=true through FILE_STANDARD_INFORMATION.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> firstEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstEnumerationResult.Status, "Expected the first directory enumeration result to succeed.");
                                FileDirectoryInformationEntry[] firstEntries = FileDirectoryInformationEntry.DecodeEntries(firstEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, firstEntries.Length, "Expected ReturnSingleEntry to constrain the first directory enumeration result.");
                                TestAssertions.Equal("alpha.txt", firstEntries[0].FileName, "Expected the first directory enumeration result to be sorted alphabetically.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> resumedEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.None,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 4096,
                                        FileNamePattern = string.Empty
                                    });
                                TestAssertions.Equal(NtStatus.Success, resumedEnumerationResult.Status, "Expected the resumed directory enumeration result to succeed.");
                                FileDirectoryInformationEntry[] resumedEntries = FileDirectoryInformationEntry.DecodeEntries(resumedEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(2, resumedEntries.Length, "Expected the resumed directory enumeration to return the remaining entries.");
                                TestAssertions.Equal("beta.log", resumedEntries[0].FileName, "Unexpected second directory enumeration entry.");
                                TestAssertions.Equal("nested", resumedEntries[1].FileName, "Unexpected final directory enumeration entry.");
                                TestAssertions.True(
                                    (resumedEntries[1].FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0,
                                    "Expected directory enumeration to preserve directory attributes on subdirectories.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> exhaustedEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.None,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 4096,
                                        FileNamePattern = string.Empty
                                    });
                                TestAssertions.Equal(NtStatus.NoMoreFiles, exhaustedEnumerationResult.Status, "Expected the directory enumeration to report exhaustion after the final entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> filteredEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.FullDirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 4096,
                                        FileNamePattern = "*.txt"
                                    });
                                TestAssertions.Equal(NtStatus.Success, filteredEnumerationResult.Status, "Expected the filtered full-directory enumeration to succeed.");
                                FileFullDirectoryInformationEntry[] filteredEntries = FileFullDirectoryInformationEntry.DecodeEntries(filteredEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, filteredEntries.Length, "Expected the filtered full-directory enumeration to return a single matching file.");
                                TestAssertions.Equal("alpha.txt", filteredEntries[0].FileName, "Unexpected filtered full-directory entry.");
                                TestAssertions.Equal(0U, filteredEntries[0].EaSize, "Expected the bounded FILE_FULL_DIR_INFORMATION slice to report EaSize=0.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryClose.Status, "Expected the directory metadata test open to close cleanly.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRenamesDirectoriesAndRejectsRenameWhileSubtreeIsOpen",
                        displayName: "Server renames directories through bounded FILE_RENAME_INFORMATION and rejects rename while the subtree is open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "archive"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "source"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "blocked-folder"));
                            File.WriteAllText(Path.Combine(sharePath, "source", "child.txt"), "seed");
                            File.WriteAllText(Path.Combine(sharePath, "blocked-folder", "open.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> childOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("source\\child.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, childOpen.Status, "Expected the child file open to succeed before the directory rename.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> childAllocationResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllocationInformation,
                                        PersistentFileId = childOpen.Response.PersistentFileId,
                                        VolatileFileId = childOpen.Response.VolatileFileId,
                                        Buffer = new FileAllocationInformation
                                        {
                                            AllocationSize = 128
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, childAllocationResult.Status, "Expected the child allocation update to succeed before the directory rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> childClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = childOpen.Response.PersistentFileId,
                                        VolatileFileId = childOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, childClose.Status, "Expected the child file open to close cleanly before the directory rename.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "source",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the source directory open to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> directoryRenameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "archive\\renamed-folder"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryRenameResult.Status, "Expected the bounded directory rename to succeed.");
                                TestAssertions.False(Directory.Exists(Path.Combine(sharePath, "source")), "Expected the source directory path to be removed after rename.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "archive", "renamed-folder")), "Expected the renamed directory path to exist after rename.");
                                TestAssertions.True(File.Exists(Path.Combine(sharePath, "archive", "renamed-folder", "child.txt")), "Expected child files to move with the renamed directory.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> renamedDirectoryNameResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.NameInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, renamedDirectoryNameResult.Status, "Expected FILE_NAME_INFORMATION on the renamed directory open to succeed.");
                                FileNameInformation renamedDirectoryName = FileNameInformation.ReadFrom(renamedDirectoryNameResult.Response.OutputBuffer);
                                TestAssertions.Equal("archive\\renamed-folder", renamedDirectoryName.FileName, "Unexpected FILE_NAME_INFORMATION path after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> movedChildOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("archive\\renamed-folder\\child.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, movedChildOpen.Status, "Expected opening the moved child file to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> movedChildStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = movedChildOpen.Response.PersistentFileId,
                                        VolatileFileId = movedChildOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, movedChildStandardResult.Status, "Expected FILE_STANDARD_INFORMATION on the moved child file to succeed.");
                                FileStandardInformation movedChildStandardInformation = FileStandardInformation.ReadFrom(movedChildStandardResult.Response.OutputBuffer);
                                TestAssertions.Equal(128UL, movedChildStandardInformation.AllocationSize, "Expected declared allocation state to move with the renamed directory subtree.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> movedChildClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = movedChildOpen.Response.PersistentFileId,
                                        VolatileFileId = movedChildOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, movedChildClose.Status, "Expected the moved child file open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> oldPathOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("source\\child.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.ObjectPathNotFound, oldPathOpen.Status, "Expected the old child path to disappear after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryClose.Status, "Expected the renamed directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> blockedDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "blocked-folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, blockedDirectoryOpen.Status, "Expected the blocked-directory open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> blockedChildOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("blocked-folder\\open.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, blockedChildOpen.Status, "Expected the child open inside the blocked directory to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> blockedRenameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = blockedDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = blockedDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 0,
                                            FileName = "archive\\blocked-renamed"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, blockedRenameResult.Status, "Expected directory renames with tracked subtree opens to be rejected.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "blocked-folder")), "Expected the blocked directory path to remain after the rejected rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> blockedChildClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = blockedChildOpen.Response.PersistentFileId,
                                        VolatileFileId = blockedChildOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, blockedChildClose.Status, "Expected the blocked child open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> blockedDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = blockedDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = blockedDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, blockedDirectoryClose.Status, "Expected the blocked directory open to close cleanly.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRejectsUnsupportedMetadataAccessPatterns",
                        displayName: "Server rejects unsupported metadata and directory-enumeration access patterns",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "restricted.txt"), "seed");
                            File.WriteAllText(Path.Combine(sharePath, "folder", "alpha.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> writeOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0x40000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, writeOnlyOpen.Status, "Expected write-only metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> deniedQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = writeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = writeOnlyOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedQueryResult.Status, "Expected FILE_BASIC_INFORMATION to require read-attributes access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> writeOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = writeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = writeOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, writeOnlyClose.Status, "Expected the write-only test open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fullOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fullOpen.Status, "Expected full-access metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> bufferTooSmallResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 8,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.BufferTooSmall, bufferTooSmallResult.Status, "Expected undersized metadata output buffers to be rejected.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> unsupportedFileSystemInfoResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.ObjectIdInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, unsupportedFileSystemInfoResult.Status, "Expected unsupported filesystem query-info classes to remain rejected.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidRenameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 1,
                                            FileName = "invalid.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidRenameResult.Status, "Expected rooted FILE_RENAME_INFORMATION_TYPE_2 requests to be rejected.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidTimestampResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue - 2
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidTimestampResult.Status, "Expected FILE_BASIC_INFORMATION timestamp values less than -2 to be rejected.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> fullClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, fullClose.Status, "Expected the full-access test open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, readOnlyOpen.Status, "Expected read-only metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> deniedSetResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = readOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyOpen.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            LastWriteTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 8, DateTimeKind.Utc).ToFileTimeUtc()),
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedSetResult.Status, "Expected FILE_BASIC_INFORMATION updates to require write-attributes access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = readOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyClose.Status, "Expected the read-only test open to close cleanly.");

                                string restrictedPath = Path.Combine(sharePath, "restricted.txt");
                                File.SetAttributes(restrictedPath, System.IO.FileAttributes.ReadOnly | System.IO.FileAttributes.Hidden);

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0x00000180U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyOpen.Status, "Expected attribute-only metadata opens on read-only files to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> clearReadOnlyResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, clearReadOnlyResult.Status, "Expected attribute-only FILE_BASIC_INFORMATION updates to clear the read-only attribute.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> attributeOnlyQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyQueryResult.Status, "Expected attribute-only metadata queries to succeed after clearing the read-only attribute.");
                                FileBasicInformation attributeOnlyBasicInformation = FileBasicInformation.ReadFrom(attributeOnlyQueryResult.Response.OutputBuffer);
                                TestAssertions.False((attributeOnlyBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.ReadOnly) != 0, "Expected FILE_BASIC_INFORMATION updates to clear the read-only attribute.");
                                TestAssertions.True((attributeOnlyBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected FILE_BASIC_INFORMATION updates to preserve the hidden attribute.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> deniedAttributeOnlyReadResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = 1,
                                        Offset = 0,
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId,
                                        MinimumCount = 0,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedAttributeOnlyReadResult.Status, "Expected attribute-only metadata opens not to grant file-read data access.");
                                TestAssertions.False((File.GetAttributes(restrictedPath) & System.IO.FileAttributes.ReadOnly) != 0, "Expected the backing file to have its read-only attribute cleared.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> attributeOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyClose.Status, "Expected the attribute-only metadata open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> fileEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, fileEnumerationResult.Status, "Expected query-directory to reject file handles that have already been closed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryWriteOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x40000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryWriteOnlyOpen.Status, "Expected the write-only directory test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> deniedEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryWriteOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryWriteOnlyOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedEnumerationResult.Status, "Expected query-directory to require read/list access on a directory handle.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryWriteOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryWriteOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryWriteOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryWriteOnlyClose.Status, "Expected the write-only directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryReadOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryReadOpen.Status, "Expected the read-only directory test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> idBothEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.IdBothDirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.Success, idBothEnumerationResult.Status, "Expected FILE_ID_BOTH_DIR_INFORMATION query-directory requests to succeed.");
                                FileIdBothDirectoryInformationEntry[] idBothEntries = FileIdBothDirectoryInformationEntry.DecodeEntries(idBothEnumerationResult.Response.OutputBuffer);
                                TestAssertions.True(idBothEntries.Length >= 1, "Expected FILE_ID_BOTH_DIR_INFORMATION enumeration to return at least one entry.");
                                TestAssertions.True(Array.Exists(idBothEntries, entry => string.Equals(entry.FileName, "alpha.txt", StringComparison.OrdinalIgnoreCase)), "Expected FILE_ID_BOTH_DIR_INFORMATION enumeration to include alpha.txt.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> bothEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.BothDirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "alpha.txt"
                                    });
                                TestAssertions.Equal(NtStatus.Success, bothEnumerationResult.Status, "Expected FILE_BOTH_DIR_INFORMATION query-directory requests to succeed.");
                                FileBothDirectoryInformationEntry[] bothEntries = FileBothDirectoryInformationEntry.DecodeEntries(bothEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, bothEntries.Length, "Expected FILE_BOTH_DIR_INFORMATION enumeration to return the requested entry.");
                                TestAssertions.Equal("alpha.txt", bothEntries[0].FileName, "Expected FILE_BOTH_DIR_INFORMATION enumeration to include alpha.txt.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> unsupportedEnumerationClassResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.StreamInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.InvalidInfoClass, unsupportedEnumerationClassResult.Status, "Expected unsupported query-directory info classes to remain rejected.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> smallBufferEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 16,
                                        FileNamePattern = "alpha.txt"
                                    });
                                TestAssertions.Equal(NtStatus.InfoLengthMismatch, smallBufferEnumerationResult.Status, "Expected undersized query-directory output buffers to be rejected.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> missingEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*.bak"
                                    });
                                TestAssertions.Equal(NtStatus.NoSuchFile, missingEnumerationResult.Status, "Expected a first-pass query-directory miss to report STATUS_NO_SUCH_FILE.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryReadClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryReadClose.Status, "Expected the read-only directory open to close cleanly.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                    ,
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRejectsInvalidSessionTreeAndOpenIdentifiersAcrossMetadataSurface",
                        displayName: "Server rejects invalid session, tree, and open identifiers across the bounded metadata surface",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerMetadataIds_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "metadata.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("metadata.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010080U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpen.Status, "Expected the metadata file test open to succeed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("folder", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U, createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the metadata directory test open to succeed.");

                                Smb2QueryInfoRequest queryInfoRequest = new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    OutputBufferLength = 512,
                                    PersistentFileId = fileOpen.Response.PersistentFileId,
                                    VolatileFileId = fileOpen.Response.VolatileFileId,
                                    InputBuffer = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryInfo(sessionId + 1, treeId, queryInfoRequest).Status, "Expected query-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryInfo(sessionId, treeId + 1, queryInfoRequest).Status, "Expected query-info requests with an unknown tree identifier to be rejected.");

                                Smb2SetInfoRequest setInfoRequest = new Smb2SetInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    PersistentFileId = fileOpen.Response.PersistentFileId,
                                    VolatileFileId = fileOpen.Response.VolatileFileId,
                                    Buffer = new FileBasicInformation
                                    {
                                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                    }.ToByteArray()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleSetInfo(sessionId + 1, treeId, setInfoRequest).Status, "Expected set-info requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleSetInfo(sessionId, treeId + 1, setInfoRequest).Status, "Expected set-info requests with an unknown tree identifier to be rejected.");

                                Smb2QueryDirectoryRequest queryDirectoryRequest = new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    Flags = Smb2QueryDirectoryFlags.RestartScans,
                                    PersistentFileId = directoryOpen.Response.PersistentFileId,
                                    VolatileFileId = directoryOpen.Response.VolatileFileId,
                                    OutputBufferLength = 512,
                                    FileNamePattern = "*"
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryDirectory(sessionId + 1, treeId, queryDirectoryRequest).Status, "Expected query-directory requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleQueryDirectory(sessionId, treeId + 1, queryDirectoryRequest).Status, "Expected query-directory requests with an unknown tree identifier to be rejected.");

                                Smb2IoctlRequest ioctlRequest = new Smb2IoctlRequest
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = fileOpen.Response.PersistentFileId,
                                    VolatileFileId = fileOpen.Response.VolatileFileId,
                                    MaxInputResponse = 16,
                                    MaxOutputResponse = 128,
                                    Flags = Smb2IoctlFlags.IsFsctl,
                                    InputBuffer = Array.Empty<byte>()
                                };
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleIoctl(sessionId + 1, treeId, ioctlRequest).Status, "Expected IOCTL requests with an unknown session identifier to be rejected.");
                                TestAssertions.Equal(NtStatus.AccessDenied, host.HandleIoctl(sessionId, treeId + 1, ioctlRequest).Status, "Expected IOCTL requests with an unknown tree identifier to be rejected.");

                                Smb2Header invalidNotifyHeader = CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 0, sessionId: sessionId + 1, treeId: treeId);
                                Smb2ChangeNotifyRequest notifyRequest = new Smb2ChangeNotifyRequest
                                {
                                    Flags = 0,
                                    OutputBufferLength = 512,
                                    PersistentFileId = directoryOpen.Response.PersistentFileId,
                                    VolatileFileId = directoryOpen.Response.VolatileFileId,
                                    CompletionFilter = FileNotifyChangeFilter.FileName
                                };
                                OpenCifsServerAsyncResponse invalidNotifySessionResponse = host.HandleChangeNotify(invalidNotifyHeader, notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifySessionResponse.Header.Status, "Expected change-notify requests with an unknown session identifier to be rejected.");

                                Smb2Header invalidNotifyTreeHeader = CreateRequestHeader(Smb2Command.ChangeNotify, messageId: 1, sessionId: sessionId, treeId: treeId + 1);
                                OpenCifsServerAsyncResponse invalidNotifyTreeResponse = host.HandleChangeNotify(invalidNotifyTreeHeader, notifyRequest);
                                TestAssertions.Equal(NtStatus.AccessDenied, invalidNotifyTreeResponse.Header.Status, "Expected change-notify requests with an unknown tree identifier to be rejected.");

                                TestAssertions.Equal(NtStatus.Success, host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId
                                    }).Status,
                                    "Expected the metadata file test open to close cleanly.");
                                TestAssertions.Equal(NtStatus.Success, host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    }).Status,
                                    "Expected the metadata directory test open to close cleanly.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server locking suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerLockingSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Locking",
                displayName: "Server byte-range locking",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Locking",
                        caseId: "ServerAppliesByteRangeLocksAndReleasesThemOnUnlockOrClose",
                        displayName: "Server applies bounded byte-range locks and rejects conflicting lock, read, and write operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "locked.txt"), "0123456789");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("locked.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U, shareAccess: 0x00000007U));
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("locked.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first locking test open to succeed.");
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the second locking test open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> exclusiveLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 2,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, exclusiveLockResult.Status, "Expected the first exclusive byte-range lock to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> conflictingLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 2,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.LockNotGranted, conflictingLockResult.Status, "Expected conflicting exclusive byte-range locks to fail.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> conflictingReadResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = 2,
                                        Offset = 2,
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        MinimumCount = 0,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, conflictingReadResult.Status, "Expected reads through a competing open to fail inside an exclusive byte-range lock.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> conflictingWriteResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 2,
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = Encoding.UTF8.GetBytes("XX"),
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, conflictingWriteResult.Status, "Expected writes through a competing open to fail inside an exclusive byte-range lock.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 2,
                                                Length = 4,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, unlockResult.Status, "Expected unlocking a previously locked byte range to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> sharedLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.SharedLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, sharedLockResult.Status, "Expected the first shared byte-range lock to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> secondSharedLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.SharedLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondSharedLockResult.Status, "Expected overlapping shared byte-range locks across opens to succeed.");

                                OpenCifsServerOperationResult<Smb2WriteResponse> sharedWriteConflictResult = host.HandleWrite(
                                    sessionId,
                                    treeId,
                                    new Smb2WriteRequest
                                    {
                                        Offset = 0,
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        Flags = Smb2WriteFlags.None,
                                        DataBuffer = Encoding.UTF8.GetBytes("YY"),
                                        WriteChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, sharedWriteConflictResult.Status, "Expected shared byte-range locks to block writes across opens.");

                                OpenCifsServerOperationResult<Smb2LockResponse> secondSharedUnlockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondSharedUnlockResult.Status, "Expected the second shared byte-range lock to unlock cleanly.");

                                OpenCifsServerOperationResult<Smb2LockResponse> closeCleanupLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 6,
                                                Length = 2,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeCleanupLockResult.Status, "Expected a second exclusive byte-range lock to succeed before close cleanup.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> firstClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstClose.Status, "Expected the first locking test open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2LockResponse> postCloseLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 6,
                                                Length = 2,
                                                Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, postCloseLockResult.Status, "Expected closing an open to release its outstanding byte-range locks.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> secondClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, secondClose.Status, "Expected the second locking test open to close cleanly.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Locking",
                        caseId: "ServerRejectsInvalidLockTargetsAndUnlockMisses",
                        displayName: "Server rejects directory locks, stale handles, and unlocks for ranges that are not held",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "locked.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> fileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("locked.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fileOpen.Status, "Expected the lock-validation file open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockMissResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = fileOpen.Response.PersistentFileId,
                                        VolatileFileId = fileOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 2,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.RangeNotLocked, unlockMissResult.Status, "Expected unlocking an unheld byte range to fail.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the directory locking test open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> directoryLockResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 1,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, directoryLockResult.Status, "Expected directory handles to reject byte-range locking.");

                                OpenCifsServerOperationResult<Smb2LockResponse> staleHandleResult = host.HandleLock(
                                    sessionId,
                                    treeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = 999,
                                        VolatileFileId = 999,
                                        Locks = new Smb2LockElement[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 1,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, staleHandleResult.Status, "Expected stale lock handles to be rejected.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server oplock suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerOplockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Oplock",
                displayName: "Server oplock-break handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Oplock",
                        caseId: "ServerGrantsExclusiveOplockAndCompletesSignedBreakAcknowledgment",
                        displayName: "Server grants exclusive oplocks and completes signed oplock-break acknowledgments",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong firstSessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(
                                    host,
                                    dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21 },
                                    expectedDialect: SmbDialect.Smb21);
                                OpenCifsServerTreeConnectResult firstTreeConnect = host.HandleTreeConnect(
                                    firstSessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstTreeConnect.Status, "Expected the first oplock tree connect to succeed.");

                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest(
                                    "shared.txt",
                                    Smb2CreateDisposition.Open,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Exclusive;
                                Smb2CreateRequestValidator.Validate(firstOpenRequest);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeConnect.TreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first oplock test open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Exclusive, firstOpen.Response.OplockLevel, "Expected the first oplock test open to receive an exclusive oplock.");

                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest(
                                        "shared.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the conflicting second open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.None, secondOpen.Response.OplockLevel, "Expected the conflicting second open not to receive an oplock grant.");

                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue an oplock-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = host.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                Smb2Header notificationHeader = parsedNotificationPacket.Entries[0].Header;
                                TestAssertions.Equal(Smb2Command.OplockBreak, notificationHeader.Command, "Expected the queued async response to surface as SMB2 OPLOCK_BREAK.");
                                TestAssertions.Equal(UInt64.MaxValue, notificationHeader.MessageId, "Expected unsolicited oplock-break notifications to use the wildcard message identifier.");
                                TestAssertions.Equal(firstSessionId, notificationHeader.SessionId, "Expected the queued oplock-break notification to target the original open session.");
                                TestAssertions.Equal(firstTreeConnect.TreeId, notificationHeader.TreeId, "Expected the queued oplock-break notification to target the original open tree.");
                                TestAssertions.True((notificationHeader.Flags & Smb2HeaderFlags.Signed) != 0, "Expected signed sessions to sign unsolicited oplock-break notifications.");
                                Smb2OplockBreakNotification notification = Smb2OplockBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                TestAssertions.Equal(Smb2OplockLevel.None, notification.OplockLevel, "Expected the bounded server oplock-break notification to lower the oplock to none.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, notification.PersistentFileId, "Expected the queued oplock-break notification to reference the original open.");

                                Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    PersistentFileId = firstOpen.Response.PersistentFileId,
                                    VolatileFileId = firstOpen.Response.VolatileFileId
                                };
                                Smb2OplockBreakAcknowledgmentValidator.Validate(acknowledgment);
                                Smb2Header acknowledgmentHeader = CreateRequestHeader(
                                    Smb2Command.OplockBreak,
                                    messageId: 0,
                                    sessionId: firstSessionId,
                                    treeId: firstTreeConnect.TreeId,
                                    flags: Smb2HeaderFlags.Signed);
                                byte[] acknowledgmentPacketBytes = CreateSignedPacketBytes(acknowledgmentHeader, acknowledgment.ToByteArray(), signingKey);
                                Smb2CompoundPacket acknowledgmentPacket = Smb2CompoundPacket.ReadFrom(acknowledgmentPacketBytes);
                                host.ValidateRequestPacket(acknowledgmentPacket, acknowledgmentPacketBytes);
                                Smb2CompoundPacket acknowledgmentResponsePacket = host.HandleCompoundRequestPacket(acknowledgmentPacket);
                                byte[] acknowledgmentResponseBytes = host.FinalizeResponsePacket(acknowledgmentResponsePacket);
                                Smb2CompoundPacket parsedAcknowledgmentResponsePacket = Smb2CompoundPacket.ReadFrom(acknowledgmentResponseBytes);
                                Smb2Header acknowledgmentResponseHeader = parsedAcknowledgmentResponsePacket.Entries[0].Header;
                                TestAssertions.Equal(NtStatus.Success, acknowledgmentResponseHeader.Status, "Expected the oplock-break acknowledgment response to succeed.");
                                Smb2OplockBreakResponse acknowledgmentResponse = Smb2OplockBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload);
                                TestAssertions.Equal(Smb2OplockLevel.None, acknowledgmentResponse.OplockLevel, "Expected the oplock-break acknowledgment response to preserve the lowered oplock level.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the conflicting second open to close cleanly after the oplock-break acknowledgment flow.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        firstSessionId,
                                        firstTreeConnect.TreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = firstOpen.Response.PersistentFileId,
                                            VolatileFileId = firstOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the first oplock test open to close cleanly after the oplock-break acknowledgment flow.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Oplock",
                        caseId: "ServerRejectsInvalidOplockBreakAcknowledgmentState",
                        displayName: "Server rejects invalid oplock-break acknowledgment state",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerOplock_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                NegotiateDialect(host, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21);
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(host);
                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest(
                                    "shared.txt",
                                    Smb2CreateDisposition.Open,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Exclusive;
                                Smb2CreateRequestValidator.Validate(firstOpenRequest);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first oplock state test open to succeed.");

                                OpenCifsServerOperationResult<Smb2OplockBreakResponse> noPendingBreakResult = host.HandleOplockBreakAcknowledgment(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2OplockBreakAcknowledgment
                                    {
                                        OplockLevel = Smb2OplockLevel.None,
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.InvalidDeviceState, noPendingBreakResult.Status, "Expected unsolicited oplock-break acknowledgments without a queued break to fail.");

                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest(
                                        "shared.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the conflicting second open to succeed before invalid acknowledgment coverage.");
                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? _), "Expected the conflicting second open to queue an oplock-break notification.");

                                OpenCifsServerOperationResult<Smb2OplockBreakResponse> wrongLevelBreakResult = host.HandleOplockBreakAcknowledgment(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2OplockBreakAcknowledgment
                                    {
                                        OplockLevel = Smb2OplockLevel.LevelII,
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.InvalidOplockProtocol, wrongLevelBreakResult.Status, "Expected oplock-break acknowledgments with the wrong lowered level to fail.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the conflicting second open to close cleanly after invalid oplock-break coverage.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        firstSessionId,
                                        firstTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = firstOpen.Response.PersistentFileId,
                                            VolatileFileId = firstOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the first oplock state test open to close cleanly after invalid acknowledgment coverage.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server lease suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerLeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Lease",
                displayName: "Server SMB 2.1 lease handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Lease",
                        caseId: "ServerGrantsReadWriteHandleLeaseAndCompletesSignedBreakAcknowledgment",
                        displayName: "Server grants a read-write-handle lease and completes a signed lease-break acknowledgment",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "seed-data");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                (ulong firstSessionId, byte[] signingKey) = AuthenticateSessionAndGetSigningKey(
                                    host,
                                    dialects: new[] { SmbDialect.Smb2002, SmbDialect.Smb21 },
                                    expectedDialect: SmbDialect.Smb21);
                                OpenCifsServerTreeConnectResult firstTreeConnect = host.HandleTreeConnect(
                                    firstSessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\LAB-SERVER\\public"
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstTreeConnect.Status, "Expected the first lease tree connect to succeed.");

                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 1);
                                }

                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest(
                                    "shared.txt",
                                    Smb2CreateDisposition.Open,
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Lease;
                                firstOpenRequest.CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                {
                                    new Smb2CreateRequestLeaseContext
                                    {
                                        LeaseKey = leaseKey,
                                        LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                                    }.ToCreateContext()
                                });
                                Smb2CreateRequestValidator.Validate(firstOpenRequest);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeConnect.TreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the first lease-backed open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, firstOpen.Response.OplockLevel, "Expected the first lease-backed open to receive an SMB 2.1 lease.");
                                Smb2CreateResponseLeaseContext firstLeaseResponse = Smb2CreateResponseLeaseContext.ReadFrom(Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts)[0]);
                                TestAssertions.SequenceEqual(leaseKey, firstLeaseResponse.LeaseKey, "Expected the lease response context to preserve the client lease key.");
                                TestAssertions.Equal(
                                    Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                    firstLeaseResponse.LeaseState,
                                    "Expected the initial lease-backed open to receive a full read-write-handle lease.");

                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = host.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest(
                                        "shared.txt",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the conflicting second open to succeed.");

                                TestAssertions.True(host.TryDequeueAsyncResponse(out OpenCifsServerAsyncResponse? notificationResponse) && notificationResponse != null, "Expected the conflicting second open to queue a lease-break notification.");
                                Smb2CompoundPacket notificationPacket = new Smb2CompoundPacket(new[]
                                {
                                    new Smb2CompoundPacketEntry(notificationResponse!.Header, notificationResponse.Payload)
                                });
                                byte[] notificationPacketBytes = host.FinalizeResponsePacket(notificationPacket);
                                Smb2CompoundPacket parsedNotificationPacket = Smb2CompoundPacket.ReadFrom(notificationPacketBytes);
                                Smb2Header notificationHeader = parsedNotificationPacket.Entries[0].Header;
                                TestAssertions.Equal(Smb2Command.OplockBreak, notificationHeader.Command, "Expected the queued lease break to surface as SMB2 OPLOCK_BREAK.");
                                TestAssertions.Equal(UInt64.MaxValue, notificationHeader.MessageId, "Expected unsolicited lease-break notifications to use the wildcard message identifier.");
                                TestAssertions.True((notificationHeader.Flags & Smb2HeaderFlags.Signed) != 0, "Expected signed sessions to sign unsolicited lease-break notifications.");
                                Smb2LeaseBreakNotification notification = Smb2LeaseBreakNotification.ReadFrom(parsedNotificationPacket.Entries[0].Payload);
                                TestAssertions.SequenceEqual(leaseKey, notification.LeaseKey, "Expected the queued lease-break notification to reference the original lease key.");
                                TestAssertions.Equal(
                                    Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                    notification.CurrentLeaseState,
                                    "Expected the queued lease-break notification to reflect the granted lease state before the break.");
                                TestAssertions.Equal(Smb2LeaseState.None, notification.NewLeaseState, "Expected the bounded server lease-break notification to lower the lease state to none.");
                                TestAssertions.True(
                                    (notification.Flags & Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired) != 0,
                                    "Expected the bounded lease-break notification to require acknowledgment.");

                                Smb2LeaseBreakAcknowledgment acknowledgment = new Smb2LeaseBreakAcknowledgment
                                {
                                    LeaseKey = leaseKey,
                                    LeaseState = Smb2LeaseState.None
                                };
                                Smb2LeaseBreakAcknowledgmentValidator.Validate(acknowledgment);
                                Smb2Header acknowledgmentHeader = CreateRequestHeader(
                                    Smb2Command.OplockBreak,
                                    messageId: 0,
                                    sessionId: firstSessionId,
                                    treeId: firstTreeConnect.TreeId,
                                    flags: Smb2HeaderFlags.Signed);
                                byte[] acknowledgmentPacketBytes = CreateSignedPacketBytes(acknowledgmentHeader, acknowledgment.ToByteArray(), signingKey);
                                Smb2CompoundPacket acknowledgmentPacket = Smb2CompoundPacket.ReadFrom(acknowledgmentPacketBytes);
                                host.ValidateRequestPacket(acknowledgmentPacket, acknowledgmentPacketBytes);
                                Smb2CompoundPacket acknowledgmentResponsePacket = host.HandleCompoundRequestPacket(acknowledgmentPacket);
                                byte[] acknowledgmentResponseBytes = host.FinalizeResponsePacket(acknowledgmentResponsePacket);
                                Smb2CompoundPacket parsedAcknowledgmentResponsePacket = Smb2CompoundPacket.ReadFrom(acknowledgmentResponseBytes);
                                Smb2LeaseBreakResponse acknowledgmentResponse = Smb2LeaseBreakResponse.ReadFrom(parsedAcknowledgmentResponsePacket.Entries[0].Payload);
                                TestAssertions.Equal(NtStatus.Success, parsedAcknowledgmentResponsePacket.Entries[0].Header.Status, "Expected the lease-break acknowledgment response to succeed.");
                                TestAssertions.Equal(Smb2LeaseState.None, acknowledgmentResponse.LeaseState, "Expected the lease-break acknowledgment response to preserve the lowered lease state.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the conflicting second open to close cleanly after the lease-break acknowledgment flow.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        firstSessionId,
                                        firstTreeConnect.TreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = firstOpen.Response.PersistentFileId,
                                            VolatileFileId = firstOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the first lease-backed open to close cleanly after the lease-break acknowledgment flow.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Lease",
                        caseId: "ServerRejectsMismatchedLeasePathsAndInvalidLeaseBreakAcknowledgments",
                        displayName: "Server rejects mismatched lease paths and invalid lease-break acknowledgments",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "first.txt"), "first");
                            File.WriteAllText(Path.Combine(sharePath, "other.txt"), "other");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                NegotiateDialect(host, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21);
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(host);
                                byte[] leaseKey = new byte[16];

                                for (int index = 0; index < leaseKey.Length; index++)
                                {
                                    leaseKey[index] = (byte)(index + 17);
                                }

                                Smb2CreateRequest firstOpenRequest = CreateFileCreateRequest("first.txt", Smb2CreateDisposition.Open);
                                firstOpenRequest.RequestedOplockLevel = Smb2OplockLevel.Lease;
                                firstOpenRequest.CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                {
                                    new Smb2CreateRequestLeaseContext
                                    {
                                        LeaseKey = leaseKey,
                                        LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching
                                    }.ToCreateContext()
                                });
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = host.HandleCreate(firstSessionId, firstTreeId, firstOpenRequest);
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial lease-backed open to succeed.");

                                TestAssertions.Equal(
                                    NtStatus.InvalidParameter,
                                    host.HandleCreate(
                                        firstSessionId,
                                        firstTreeId,
                                        new Smb2CreateRequest
                                        {
                                            RequestedOplockLevel = Smb2OplockLevel.Lease,
                                            ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                            DesiredAccess = 0x80000000U,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Normal,
                                            ShareAccess = 0x00000007U,
                                            CreateDisposition = Smb2CreateDisposition.Open,
                                            CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                            Name = "other.txt",
                                            CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                            {
                                                new Smb2CreateRequestLeaseContext
                                                {
                                                    LeaseKey = leaseKey,
                                                    LeaseState = Smb2LeaseState.ReadCaching
                                                }.ToCreateContext()
                                            })
                                        }).Status,
                                    "Expected the same lease key to be rejected for a different file path.");

                                OpenCifsServerOperationResult<Smb2LeaseBreakResponse> invalidAckResult = host.HandleLeaseBreakAcknowledgment(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2LeaseBreakAcknowledgment
                                    {
                                        LeaseKey = leaseKey,
                                        LeaseState = Smb2LeaseState.None
                                    });
                                TestAssertions.Equal(NtStatus.InvalidDeviceState, invalidAckResult.Status, "Expected lease-break acknowledgments without a pending break to fail.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    host.HandleClose(
                                        firstSessionId,
                                        firstTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = firstOpen.Response.PersistentFileId,
                                            VolatileFileId = firstOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the initial lease-backed open to close cleanly after negative lease coverage.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server durable-handle suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerDurableHandleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Durable",
                displayName: "Server durable-handle reconnect handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerDetachesDurableBatchOpenAcrossTransportDisconnectAndReconnectsIt",
                        displayName: "Server detaches a durable batch open across transport disconnect and reconnects it on a new session and tree",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(firstHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableCreateRequest("shared.txt"));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, firstOpen.Response.OplockLevel, "Expected the initial durable open to receive a batch oplock.");
                                TestAssertions.Equal(1, Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts).Length, "Expected the initial durable open to return a durable response context.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(secondHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the durable reconnect to succeed on a new session and tree.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, reconnectResult.Response.PersistentFileId, "Expected durable reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    reconnectResult.Response.VolatileFileId == firstOpen.Response.VolatileFileId,
                                    "Expected durable reconnect to allocate a new volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, reconnectResult.Response.OplockLevel, "Expected durable reconnect to preserve the granted batch oplock.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2ReadRequest
                                    {
                                        PersistentFileId = reconnectResult.Response.PersistentFileId,
                                        VolatileFileId = reconnectResult.Response.VolatileFileId,
                                        Length = 12,
                                        Offset = 0,
                                        MinimumCount = 1
                                    });
                                TestAssertions.Equal(NtStatus.Success, readResult.Status, "Expected durable reconnect reads to succeed.");
                                TestAssertions.Equal("durable-data", Encoding.UTF8.GetString(readResult.Response.DataBuffer), "Expected the reconnected durable open to preserve file access.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = reconnectResult.Response.PersistentFileId,
                                            VolatileFileId = reconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the reconnected durable open to close cleanly.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerDetachesDurableLeaseOpenAcrossTransportDisconnectAndReconnectsIt",
                        displayName: "Server detaches a durable lease-backed open across transport disconnect and reconnects it on a new session and tree",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurableLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                Guid durableClientGuid = Guid.NewGuid();
                                byte[] leaseKey = Hex("0102030405060708090A0B0C0D0E0F10");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                NegotiateDialect(firstHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(firstHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableLeaseCreateRequest("shared.txt", leaseKey, leaseState));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable lease-backed open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, firstOpen.Response.OplockLevel, "Expected the initial durable lease-backed open to receive an SMB 2.1 lease.");
                                Smb2CreateContext[] initialCreateContexts = Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts);
                                TestAssertions.Equal(2, initialCreateContexts.Length, "Expected the initial durable lease-backed open to return both durable and lease response contexts.");
                                TestAssertions.True(Smb2DurableHandleResponseContext.IsMatch(initialCreateContexts[0]), "Expected the first create response context to advertise durable reconnect state.");
                                Smb2CreateResponseLeaseContext initialLeaseResponse = Smb2CreateResponseLeaseContext.ReadFrom(initialCreateContexts[1]);
                                TestAssertions.SequenceEqual(leaseKey, initialLeaseResponse.LeaseKey, "Expected the initial durable lease response to preserve the lease key.");
                                TestAssertions.Equal(leaseState, initialLeaseResponse.LeaseState, "Expected the initial durable lease response to preserve the granted lease state.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                NegotiateDialect(secondHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(secondHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableLeaseReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        leaseKey,
                                        leaseState));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the durable lease reconnect to succeed on a new session and tree.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, reconnectResult.Response.PersistentFileId, "Expected durable lease reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(
                                    reconnectResult.Response.VolatileFileId == firstOpen.Response.VolatileFileId,
                                    "Expected durable lease reconnect to allocate a new volatile file identifier.");
                                TestAssertions.Equal(Smb2OplockLevel.Lease, reconnectResult.Response.OplockLevel, "Expected durable lease reconnect to preserve the lease-backed oplock level.");
                                Smb2CreateContext[] reconnectCreateContexts = Smb2CreateContextCodec.Decode(reconnectResult.Response.CreateContexts);
                                TestAssertions.Equal(2, reconnectCreateContexts.Length, "Expected the durable lease reconnect response to return both durable and lease contexts.");
                                TestAssertions.True(Smb2DurableHandleResponseContext.IsMatch(reconnectCreateContexts[0]), "Expected the reconnect response to retain durable reconnect state.");
                                Smb2CreateResponseLeaseContext reconnectLeaseResponse = Smb2CreateResponseLeaseContext.ReadFrom(reconnectCreateContexts[1]);
                                TestAssertions.SequenceEqual(leaseKey, reconnectLeaseResponse.LeaseKey, "Expected the reconnect lease response to preserve the original lease key.");
                                TestAssertions.Equal(leaseState, reconnectLeaseResponse.LeaseState, "Expected the reconnect lease response to preserve the granted lease state.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> readResult = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2ReadRequest
                                    {
                                        PersistentFileId = reconnectResult.Response.PersistentFileId,
                                        VolatileFileId = reconnectResult.Response.VolatileFileId,
                                        Length = 32,
                                        Offset = 0,
                                        MinimumCount = 1
                                    });
                                TestAssertions.Equal(NtStatus.Success, readResult.Status, "Expected durable lease reconnect reads to succeed.");
                                TestAssertions.Equal("durable-lease-data", Encoding.UTF8.GetString(readResult.Response.DataBuffer), "Expected the reconnected durable lease open to preserve file access.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = reconnectResult.Response.PersistentFileId,
                                            VolatileFileId = reconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the reconnected durable lease open to close cleanly.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerDetachesSmb302DurableHandleV2BatchOpenAcrossTransportDisconnectAndReconnectsIt",
                        displayName: "Server detaches an SMB 3.0.2 durable-handle v2 batch open across transport disconnect and reconnects it on a new session and tree",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurableV2_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-v2-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName,
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = false
                            }, sharedState);
                            OpenCifsServerHost secondHost = new OpenCifsServerHost(new OpenCifsServerOptions
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName,
                                MinimumDialect = SmbDialect.Smb302,
                                MaximumDialect = SmbDialect.Smb302,
                                RequireEncryptionForSmb3 = false
                            }, sharedState);
                            RegisterDefaultShareAndAccount(firstHost, sharePath);
                            RegisterDefaultShareAndAccount(secondHost, sharePath);

                            try
                            {
                                Guid clientGuid = Guid.NewGuid();
                                Guid createGuid = Guid.NewGuid();
                                NegotiateDialect(firstHost, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302, clientGuid);
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(firstHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableHandleV2CreateRequest("shared.txt", createGuid));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial SMB 3.0.2 durable-handle v2 open to succeed.");
                                TestAssertions.Equal(Smb2OplockLevel.Batch, firstOpen.Response.OplockLevel, "Expected the initial SMB 3.0.2 durable-handle v2 open to receive a batch oplock.");
                                Smb2CreateContext[] initialCreateContexts = Smb2CreateContextCodec.Decode(firstOpen.Response.CreateContexts);
                                TestAssertions.Equal(1, initialCreateContexts.Length, "Expected the initial SMB 3.0.2 durable-handle v2 open to return a single durable response context.");
                                TestAssertions.True(Smb2DurableHandleResponseV2Context.IsMatch(initialCreateContexts[0]), "Expected the initial SMB 3.0.2 durable open to return a durable-handle v2 response context.");
                                Smb2DurableHandleResponseV2Context initialDurableResponse = Smb2DurableHandleResponseV2Context.ReadFrom(initialCreateContexts[0]);
                                TestAssertions.Equal(300000U, initialDurableResponse.Timeout, "Expected the bounded SMB 3.0.2 durable-handle v2 timeout to clamp to the managed default.");
                                TestAssertions.Equal(Smb2DurableHandleFlags.None, initialDurableResponse.Flags, "Expected the bounded SMB 3.0.2 durable-handle v2 response to stay non-persistent.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                NegotiateDialect(secondHost, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302, clientGuid);
                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(secondHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableHandleV2ReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        createGuid));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the SMB 3.0.2 durable-handle v2 reconnect to succeed on a new session and tree.");
                                TestAssertions.Equal(firstOpen.Response.PersistentFileId, reconnectResult.Response.PersistentFileId, "Expected SMB 3.0.2 durable-handle v2 reconnect to preserve the persistent file identifier.");
                                TestAssertions.False(reconnectResult.Response.VolatileFileId == firstOpen.Response.VolatileFileId, "Expected SMB 3.0.2 durable-handle v2 reconnect to allocate a new volatile file identifier.");
                                Smb2CreateContext[] reconnectCreateContexts = Smb2CreateContextCodec.Decode(reconnectResult.Response.CreateContexts);
                                TestAssertions.Equal(1, reconnectCreateContexts.Length, "Expected the SMB 3.0.2 durable-handle v2 reconnect to return a single durable response context.");
                                TestAssertions.True(Smb2DurableHandleResponseV2Context.IsMatch(reconnectCreateContexts[0]), "Expected the SMB 3.0.2 durable-handle v2 reconnect response to retain a durable-handle v2 response context.");
                                Smb2DurableHandleResponseV2Context reconnectDurableResponse = Smb2DurableHandleResponseV2Context.ReadFrom(reconnectCreateContexts[0]);
                                TestAssertions.Equal(300000U, reconnectDurableResponse.Timeout, "Expected SMB 3.0.2 durable-handle v2 reconnect to preserve the bounded durable timeout.");
                                TestAssertions.Equal(Smb2DurableHandleFlags.None, reconnectDurableResponse.Flags, "Expected SMB 3.0.2 durable-handle v2 reconnect to stay non-persistent.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerRejectsPersistentDurableHandleV2HintsInBoundedSmb302Slice",
                        displayName: "Server rejects persistent durable-handle v2 hints in the bounded SMB 3.0.2 slice",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurablePersistent_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");

                            try
                            {
                                OpenCifsServerHost host = new OpenCifsServerHost(new OpenCifsServerOptions
                                {
                                    ServerName = TestEnvironmentDefaults.DefaultServerName,
                                    MinimumDialect = SmbDialect.Smb302,
                                    MaximumDialect = SmbDialect.Smb302,
                                    RequireEncryptionForSmb3 = false
                                });
                                RegisterDefaultShareAndAccount(host, sharePath);
                                NegotiateDialect(host, new[] { SmbDialect.Smb302 }, SmbDialect.Smb302);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateDurableHandleV2CreateRequest(
                                        "shared.txt",
                                        Guid.NewGuid(),
                                        flags: Smb2DurableHandleFlags.Persistent));
                                TestAssertions.Equal(NtStatus.InvalidParameter, createResult.Status, "Expected the bounded SMB 3.0.2 slice to reject persistent durable-handle v2 hints.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerRejectsMismatchedDurableReconnectAndKeepsTheDetachedOpenAvailable",
                        displayName: "Server rejects mismatched durable reconnect paths and keeps the detached open available for the correct reconnect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(firstHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableCreateRequest("shared.txt"));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable open to succeed.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(secondHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> invalidReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "wrong.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidReconnectResult.Status, "Expected reconnects with the wrong path to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.Success, validReconnectResult.Status, "Expected the detached durable open to remain reconnectable after a rejected mismatched reconnect.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = validReconnectResult.Response.PersistentFileId,
                                            VolatileFileId = validReconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the successfully reconnected durable open to close cleanly.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerRejectsMissingOrMismatchedLeaseContextDuringDurableReconnectAndKeepsTheDetachedOpenAvailable",
                        displayName: "Server rejects missing or mismatched lease reconnect state and keeps the detached durable open available for the correct retry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurableLease_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-lease-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                Guid durableClientGuid = Guid.NewGuid();
                                byte[] leaseKey = Hex("1112131415161718191A1B1C1D1E1F20");
                                byte[] wrongLeaseKey = Hex("2122232425262728292A2B2C2D2E2F30");
                                Smb2LeaseState leaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching;
                                NegotiateDialect(firstHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(firstHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableLeaseCreateRequest("shared.txt", leaseKey, leaseState));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable lease-backed open to succeed.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                NegotiateDialect(secondHost, new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }, SmbDialect.Smb21, durableClientGuid);
                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(secondHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> missingLeaseReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, missingLeaseReconnectResult.Status, "Expected durable lease reconnect requests without a lease create context to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> wrongLeaseReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableLeaseReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        wrongLeaseKey,
                                        leaseState));
                                TestAssertions.Equal(NtStatus.ObjectNameNotFound, wrongLeaseReconnectResult.Status, "Expected durable lease reconnect requests with the wrong lease key to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> validReconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableLeaseReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId,
                                        leaseKey,
                                        leaseState));
                                TestAssertions.Equal(NtStatus.Success, validReconnectResult.Status, "Expected the detached durable lease open to remain reconnectable after rejected retries.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = validReconnectResult.Response.PersistentFileId,
                                            VolatileFileId = validReconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the successfully reconnected durable lease open to close cleanly.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Durable",
                        caseId: "ServerPreservesDurableByteRangeLocksAcrossTransportDisconnectAndReconnect",
                        displayName: "Server preserves durable byte-range locks across transport disconnect and reconnect",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDurable_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "shared.txt"), "durable-data");
                            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
                            OpenCifsServerHost firstHost = CreateServerHost(sharePath, sharedState: sharedState);
                            OpenCifsServerHost secondHost = CreateServerHost(sharePath, sharedState: sharedState);

                            try
                            {
                                (ulong firstSessionId, uint firstTreeId) = AuthenticateAndConnectTree(firstHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> firstOpen = firstHost.HandleCreate(
                                    firstSessionId,
                                    firstTreeId,
                                    CreateDurableCreateRequest("shared.txt"));
                                TestAssertions.Equal(NtStatus.Success, firstOpen.Status, "Expected the initial durable open to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> initialLockResult = firstHost.HandleLock(
                                    firstSessionId,
                                    firstTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = firstOpen.Response.PersistentFileId,
                                        VolatileFileId = firstOpen.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, initialLockResult.Status, "Expected the durable open to acquire its initial exclusive byte-range lock.");

                                lock (firstHost.SyncRoot)
                                {
                                    firstHost.HandleTransportDisconnect();
                                    firstHost.UnregisterFromSharedState();
                                }

                                (ulong secondSessionId, uint secondTreeId) = AuthenticateAndConnectTree(secondHost);
                                OpenCifsServerOperationResult<Smb2CreateResponse> secondOpen = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateFileCreateRequest("shared.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, secondOpen.Status, "Expected the competing open to succeed while the durable handle is detached.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> detachedReadConflict = secondHost.HandleRead(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2ReadRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Length = 4,
                                        Offset = 0,
                                        MinimumCount = 1
                                    });
                                TestAssertions.Equal(NtStatus.FileLockConflict, detachedReadConflict.Status, "Expected detached durable locks to block overlapping reads.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> reconnectResult = secondHost.HandleCreate(
                                    secondSessionId,
                                    secondTreeId,
                                    CreateDurableReconnectCreateRequest(
                                        "shared.txt",
                                        firstOpen.Response.PersistentFileId,
                                        firstOpen.Response.VolatileFileId));
                                TestAssertions.Equal(NtStatus.Success, reconnectResult.Status, "Expected the durable reconnect to succeed.");

                                OpenCifsServerOperationResult<Smb2LockResponse> reconnectedLockConflict = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.LockNotGranted, reconnectedLockConflict.Status, "Expected the reconnected durable open to restore its exclusive byte-range lock ownership.");

                                OpenCifsServerOperationResult<Smb2LockResponse> unlockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = reconnectResult.Response.PersistentFileId,
                                        VolatileFileId = reconnectResult.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.Unlock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, unlockResult.Status, "Expected the reconnected durable open to unlock its restored byte-range lock.");

                                OpenCifsServerOperationResult<Smb2LockResponse> postUnlockLockResult = secondHost.HandleLock(
                                    secondSessionId,
                                    secondTreeId,
                                    new Smb2LockRequest
                                    {
                                        PersistentFileId = secondOpen.Response.PersistentFileId,
                                        VolatileFileId = secondOpen.Response.VolatileFileId,
                                        Locks = new[]
                                        {
                                            new Smb2LockElement
                                            {
                                                Offset = 0,
                                                Length = 4,
                                                Flags = Smb2LockFlags.ExclusiveLock
                                            }
                                        }
                                    });
                                TestAssertions.Equal(NtStatus.Success, postUnlockLockResult.Status, "Expected competing opens to acquire the range after the durable reconnect path unlocks it.");

                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = secondOpen.Response.PersistentFileId,
                                            VolatileFileId = secondOpen.Response.VolatileFileId
                                        }).Status,
                                    "Expected the competing open to close cleanly.");
                                TestAssertions.Equal(
                                    NtStatus.Success,
                                    secondHost.HandleClose(
                                        secondSessionId,
                                        secondTreeId,
                                        new Smb2CloseRequest
                                        {
                                            PersistentFileId = reconnectResult.Response.PersistentFileId,
                                            VolatileFileId = reconnectResult.Response.VolatileFileId
                                        }).Status,
                                    "Expected the reconnected durable open to close cleanly.");
                            }
                            finally
                            {
                                secondHost.UnregisterFromSharedState();

                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server IOCTL suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerIoctlSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Ioctl",
                displayName: "Server IOCTL handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Ioctl",
                        caseId: "ServerHandlesValidateNegotiateAndSnapshotEnumerationAndRejectsUnsupportedWildcardAndStaleHandles",
                        displayName: "Server handles validate-negotiate and bounded snapshot enumeration and rejects unsupported wildcard IOCTLs and stale open identifiers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerIoctl_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
                                {
                                    ClientGuid = Guid.Parse("AF974724-128B-4C14-B096-6B7367D04542"),
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.None,
                                    Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                                };
                                Smb2NegotiateResponse negotiateResponse = host.HandleNegotiate(negotiateRequest);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2IoctlResponse> validateResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 256,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new ValidateNegotiateInfoRequest
                                        {
                                            Capabilities = negotiateRequest.Capabilities,
                                            ClientGuid = negotiateRequest.ClientGuid,
                                            SecurityMode = negotiateRequest.SecurityMode,
                                            Dialects = negotiateRequest.Dialects
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, validateResult.Status, "Expected validate-negotiate FSCTL requests to succeed after negotiate.");
                                ValidateNegotiateInfoResponse validateResponse = ValidateNegotiateInfoResponse.ReadFrom(validateResult.Response.OutputBuffer);
                                TestAssertions.Equal(negotiateResponse.ServerGuid, validateResponse.ServerGuid, "Expected validate-negotiate responses to return the negotiated server GUID.");
                                TestAssertions.Equal(negotiateResponse.Dialect, validateResponse.Dialect, "Expected validate-negotiate responses to return the negotiated dialect.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> reorderedValidateResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 256,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new ValidateNegotiateInfoRequest
                                        {
                                            Capabilities = negotiateRequest.Capabilities,
                                            ClientGuid = negotiateRequest.ClientGuid,
                                            SecurityMode = negotiateRequest.SecurityMode,
                                            Dialects = new[] { SmbDialect.Smb21, SmbDialect.Smb2002 }
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, reorderedValidateResult.Status, "Expected validate-negotiate FSCTL requests with reordered offered dialects to be rejected.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("notes.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected the IOCTL test open to succeed.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> snapshotResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, snapshotResult.Status, "Expected bounded snapshot enumeration to succeed for a tracked open.");
                                Smb2IoctlResponseValidator.Validate(snapshotResult.Response);
                                SrvSnapshotArray snapshotArray = SrvSnapshotArray.ReadFrom(snapshotResult.Response.OutputBuffer);
                                TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, snapshotResult.Response.CtlCode, "Expected snapshot enumeration to preserve the FSCTL code.");
                                TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Expected the bounded snapshot enumeration slice to return no snapshots.");
                                TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected the bounded snapshot enumeration slice to return an empty snapshot list.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> wildcardResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, wildcardResult.Status, "Expected unsupported wildcard-file-id FSCTL requests to remain non-implemented.");
                                TestAssertions.Equal(UInt64.MaxValue, wildcardResult.Response.PersistentFileId, "Expected wildcard IOCTL responses to preserve the wildcard file identifier.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> staleHandleResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = 999,
                                        VolatileFileId = 999,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, staleHandleResult.Status, "Expected stale IOCTL file identifiers to be rejected.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Ioctl",
                        caseId: "ServerRejectsInvalidIoctlShapesAndHandlesCompoundedDispatch",
                        displayName: "Server rejects invalid IOCTL shapes and dispatches unsupported compounded IOCTL requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerIoctlCompound_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "compound.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
                                {
                                    ClientGuid = Guid.Parse("0D144B50-B9BC-49FF-B8D1-C59111145940"),
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.None,
                                    Dialects = new[] { SmbDialect.Smb2002 }
                                };
                                host.HandleNegotiate(negotiateRequest);
                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);

                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("compound.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected the compounded IOCTL test open to succeed.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> nonFsctlResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxOutputResponse = 256,
                                        Flags = Smb2IoctlFlags.None,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, nonFsctlResult.Status, "Expected non-FSCTL IOCTL requests to remain rejected.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> invalidSnapshotInputResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 256,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new byte[] { 0x01 }
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidSnapshotInputResult.Status, "Expected snapshot enumeration requests with a non-empty input buffer to be rejected.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> shortSnapshotOutputResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 8,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, shortSnapshotOutputResult.Status, "Expected snapshot enumeration requests with too-small output limits to be rejected.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> missingWildcardResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxOutputResponse = 256,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, missingWildcardResult.Status, "Expected connection-scoped FSCTL requests without wildcard file identifiers to be rejected.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> mismatchedValidateResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxOutputResponse = 256,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new ValidateNegotiateInfoRequest
                                        {
                                            Capabilities = negotiateRequest.Capabilities,
                                            ClientGuid = Guid.Parse("2259C69D-0AA7-4CAA-8A8A-4A5B87F93EC5"),
                                            SecurityMode = negotiateRequest.SecurityMode,
                                            Dialects = negotiateRequest.Dialects
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, mismatchedValidateResult.Status, "Expected validate-negotiate FSCTL requests with mismatched client state to be rejected.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> oversizedResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxOutputResponse = 65537,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, oversizedResult.Status, "Expected oversized IOCTL transaction sizes to be rejected.");

                                Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                    new List<Smb2CompoundPacketEntry>
                                    {
                                        new Smb2CompoundPacketEntry(
                                            CreateRequestHeader(Smb2Command.Ioctl, messageId: 0, sessionId: sessionId, treeId: treeId),
                                            new Smb2IoctlRequest
                                            {
                                                CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                                PersistentFileId = UInt64.MaxValue,
                                                VolatileFileId = UInt64.MaxValue,
                                                MaxOutputResponse = 256,
                                                Flags = Smb2IoctlFlags.IsFsctl,
                                                InputBuffer = Array.Empty<byte>()
                                            }.ToByteArray())
                                    });
                                Smb2CompoundPacket responsePacket = host.HandleCompoundRequestPacket(Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray()));
                                TestAssertions.Equal(1, responsePacket.Entries.Count, "Unexpected compounded IOCTL response entry count.");
                                TestAssertions.Equal(NtStatus.NotSupported, responsePacket.Entries[0].Header.Status, "Expected compounded unsupported IOCTL requests to stay non-implemented.");

                                Smb2IoctlResponse compoundedResponse = Smb2IoctlResponse.ReadFrom(
                                    Smb2CompoundPayloadHelper.TrimResponsePayload(responsePacket.Entries[0].Header.Command, responsePacket.Entries[0].Payload));
                                Smb2IoctlResponseValidator.Validate(compoundedResponse);
                                TestAssertions.Equal((uint)FsctlCode.QueryNetworkInterfaceInfo, compoundedResponse.CtlCode, "Unexpected compounded IOCTL response control code.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Ioctl",
                        caseId: "ServerIoctlCallbacksReturnApplicationControlledResponsesAndRejectPassthroughUnsupportedRequests",
                        displayName: "Server IOCTL callbacks return application-controlled responses and reject unsupported passthrough requests",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsIoctlCallbacks_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");
                            int ioctlCallbackCount = 0;

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(
                                    sharePath,
                                    new OpenCifsServerRequestCallbacks
                                    {
                                        IoctlCallback = context =>
                                        {
                                            ioctlCallbackCount++;
                                            TestAssertions.Equal("public", context.ShareName, "Expected the IOCTL callback to observe the resolved share name.");
                                            TestAssertions.Equal(Path.Combine(sharePath, "notes.txt"), context.FullPath, "Expected the IOCTL callback to observe the resolved file path.");

                                            if (context.Request.CtlCode != (uint)FsctlCode.SrvEnumerateSnapshots)
                                            {
                                                return null;
                                            }

                                            return new OpenCifsServerIoctlCallbackResult
                                            {
                                                Status = NtStatus.Success,
                                                Response = new Smb2IoctlResponse
                                                {
                                                    Flags = 0,
                                                    InputBuffer = Array.Empty<byte>(),
                                                    OutputBuffer = new SrvSnapshotArray
                                                    {
                                                        NumberOfSnapshots = 2,
                                                        Snapshots = new[]
                                                        {
                                                            "@GMT-2024.05.06-07.08.09",
                                                            "@GMT-2024.05.07-07.08.09"
                                                        }
                                                    }.ToByteArray()
                                                }
                                            };
                                        }
                                    });

                                (ulong sessionId, uint treeId) = AuthenticateAndConnectTree(host);
                                OpenCifsServerOperationResult<Smb2CreateResponse> openResult = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("notes.txt", Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.Success, openResult.Status, "Expected the IOCTL callback test open to succeed.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> callbackSnapshotResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, callbackSnapshotResult.Status, "Expected the IOCTL callback to return an application-controlled snapshot response.");
                                SrvSnapshotArray callbackSnapshots = SrvSnapshotArray.ReadFrom(callbackSnapshotResult.Response.OutputBuffer);
                                TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, callbackSnapshotResult.Response.CtlCode, "Expected the callback response to preserve the requested FSCTL code.");
                                TestAssertions.Equal(openResult.Response.PersistentFileId, callbackSnapshotResult.Response.PersistentFileId, "Expected the callback response to preserve the open persistent file identifier.");
                                TestAssertions.Equal(openResult.Response.VolatileFileId, callbackSnapshotResult.Response.VolatileFileId, "Expected the callback response to preserve the open volatile file identifier.");
                                TestAssertions.Equal(2U, callbackSnapshots.NumberOfSnapshots, "Expected the callback response to expose the application-controlled snapshot count.");
                                TestAssertions.Equal(2, callbackSnapshots.Snapshots.Length, "Expected the callback response to return two snapshot tokens.");
                                TestAssertions.Equal("@GMT-2024.05.06-07.08.09", callbackSnapshots.Snapshots[0], "Unexpected first callback snapshot token.");
                                TestAssertions.Equal("@GMT-2024.05.07-07.08.09", callbackSnapshots.Snapshots[1], "Unexpected second callback snapshot token.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> passthroughResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = 0x000900C0U,
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, passthroughResult.Status, "Expected non-overridden FSCTLs to fall through to the bounded unsupported path.");
                                TestAssertions.Equal(2, ioctlCallbackCount, "Expected the IOCTL callback to run for both overridden and passthrough requests.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = openResult.Response.PersistentFileId,
                                        VolatileFileId = openResult.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected the IOCTL callback test open to close cleanly.");
                            }
                            finally
                            {
                                if (Directory.Exists(sharePath))
                                {
                                    Directory.Delete(sharePath, recursive: true);
                                }
                            }

                            return Task.CompletedTask;
                        })
                });
        }

        private static OpenCifsServerHost CreateServerHost(string? sharePath = null, OpenCifsServerRequestCallbacks? callbacks = null, OpenCifsServerSharedState? sharedState = null, bool requireEncryptionForSmb3 = true)
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

        private static void RegisterDefaultShareAndAccount(OpenCifsServerHost host, string sharePath)
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

        private static Smb2CreateRequest CreateDurableCreateRequest(string path)
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

        private static Smb2CreateRequest CreateDurableHandleV2CreateRequest(string path, Guid createGuid, Smb2DurableHandleFlags flags = Smb2DurableHandleFlags.None)
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

        private static Smb2CreateRequest CreateDurableLeaseCreateRequest(string path, byte[] leaseKey, Smb2LeaseState leaseState)
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

        private static Smb2CreateRequest CreateDurableReconnectCreateRequest(string path, ulong persistentFileId, ulong volatileFileId)
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

        private static Smb2CreateRequest CreateDurableHandleV2ReconnectCreateRequest(string path, ulong persistentFileId, ulong volatileFileId, Guid createGuid, Smb2DurableHandleFlags flags = Smb2DurableHandleFlags.None)
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

        private static Smb2CreateRequest CreateDurableLeaseReconnectCreateRequest(
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

        /// <summary>
        /// Build the bounded server-side DFS referral configuration suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerDfsConfigurationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.DfsConfiguration",
                displayName: "Bounded server-side DFS referral configuration",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.DfsConfiguration",
                        caseId: "ServerHostBuilderRegistersValidatesAndRejectsDuplicateDfsReferrals",
                        displayName: "Server host builder registers, validates, and rejects duplicate DFS referrals",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName
                            });

                            TestAssertions.Throws<ArgumentNullException>(
                                () => builder.AddDfsReferral(null!),
                                "Expected null DFS referrals to be rejected with an ArgumentNullException.");

                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => builder.AddDfsReferral(new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = "namespace",
                                    NamespacePath = "/link",
                                    TargetServerName = "target",
                                    TargetShareName = "share",
                                    TimeToLiveSeconds = 0
                                }),
                                "Expected zero TTL DFS referrals to be rejected during validation.");

                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = "namespace",
                                NamespacePath = "/link",
                                TargetServerName = "target",
                                TargetShareName = "share",
                                TimeToLiveSeconds = 600
                            };
                            builder.AddDfsReferral(referral);

                            TestAssertions.Throws<OpenCifsServerConfigurationException>(
                                () => builder.AddDfsReferral(new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = "namespace",
                                    NamespacePath = "/link",
                                    TargetServerName = "target",
                                    TargetShareName = "share",
                                    TimeToLiveSeconds = 600
                                }),
                                "Expected duplicate DFS referrals to be rejected.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.DfsConfiguration",
                        caseId: "ServerDfsReferralClonePreservesAllConfiguredFields",
                        displayName: "Server DFS referral clone preserves all configured fields",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsServerDfsReferral referral = new OpenCifsServerDfsReferral
                            {
                                NamespaceShareName = "ns",
                                NamespacePath = "/branch",
                                TargetServerName = "files-target",
                                TargetShareName = "data",
                                TargetPath = "/team",
                                TimeToLiveSeconds = 900
                            };
                            referral.Validate();
                            OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                            {
                                ServerName = TestEnvironmentDefaults.DefaultServerName
                            });
                            builder.AddDfsReferral(referral);

                            referral.NamespaceShareName = "mutated";
                            referral.TargetPath = "/mutated";

                            OpenCifsServerHost host = builder.BuildHost();
                            TestAssertions.True(host != null, "Expected the host to build cleanly with a registered DFS referral.");

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the server malformed-input mutation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ServerMutationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Server.Mutation",
                displayName: "Server malformed-input mutation smoke",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Server.Mutation",
                        caseId: "ServerNegotiatesBaselineDirectTcpCorpusBeforeMutation",
                        displayName: "Server negotiates the baseline direct-TCP corpus before mutation",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(port, token).ConfigureAwait(false);

                            try
                            {
                                foreach ((string _, byte[] payload) in BuildDirectTcpMutationRequestBaselines())
                                {
                                    await AssertNegotiatesDirectTcpRequestAsync(port, payload, token).ConfigureAwait(false);
                                }
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                            }
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Mutation",
                        caseId: "ServerSurvivesMalformedDirectTcpMutationBurstAndOnlySurfacesProtocolExceptions",
                        displayName: "Server survives a malformed direct-TCP mutation burst and only surfaces bounded protocol exceptions",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int port = AllocateTcpPort();
                            List<Exception> capturedExceptions = new List<Exception>();
                            (CancellationTokenSource serverCancellationTokenSource, Task serverTask) = await StartDirectTcpServerAsync(
                                port,
                                exception =>
                                {
                                    lock (capturedExceptions)
                                    {
                                        capturedExceptions.Add(exception);
                                    }
                                },
                                token).ConfigureAwait(false);

                            int totalMutations = 0;
                            string traceRootPath = TestPathUtilities.CreateUniqueDirectory("OpenCifsMutationTrace_");
                            PacketCaptureTraceWriter traceWriter = new PacketCaptureTraceWriter(traceRootPath, "ServerDirectTcpMutationBurst");

                            try
                            {
                                foreach ((string name, byte[] payload) in BuildDirectTcpMutationRequestBaselines())
                                {
                                    traceWriter.Capture(name + "-baseline", payload);
                                    IReadOnlyList<byte[]> mutations = MutationTestUtilities.CreateDeterministicMutationCorpus(
                                        payload,
                                        randomSeed: 0x53525652 ^ DeterministicTestHash.ComputeInt32(name),
                                        randomCount: 32);

                                    if (mutations.Count > 0)
                                    {
                                        traceWriter.Capture(name + "-mutation-000", mutations[0]);
                                    }

                                    for (int index = 0; index < mutations.Count; index++)
                                    {
                                        await SendMalformedDirectTcpFrameAsync(port, mutations[index], token).ConfigureAwait(false);
                                    }

                                    totalMutations += mutations.Count;
                                }

                                byte[] recoveryPayload = BuildDirectTcpMutationRequestBaselines()[0].Payload;
                                traceWriter.Capture("recovery-negotiate", recoveryPayload);
                                FileAssertions.AssertExists(traceWriter.WriteManifest());
                                await AssertNegotiatesDirectTcpRequestAsync(port, recoveryPayload, token).ConfigureAwait(false);
                            }
                            finally
                            {
                                await StopDirectTcpServerAsync(serverCancellationTokenSource, serverTask).ConfigureAwait(false);
                                TestPathUtilities.DeleteDirectoryForcefully(traceRootPath);
                            }

                            TestAssertions.True(totalMutations >= 100, "Expected the server malformed-input mutation burst to execute at least 100 mutated direct-TCP requests.");

                            lock (capturedExceptions)
                            {
                                TestAssertions.True(capturedExceptions.Count > 0, "Expected the malformed direct-TCP mutation burst to surface at least one protocol exception.");

                                for (int index = 0; index < capturedExceptions.Count; index++)
                                {
                                    Exception exception = capturedExceptions[index];
                                    bool expected = exception is ProtocolEncodingException || exception is ProtocolValidationException;
                                    TestAssertions.True(
                                        expected,
                                        "Expected only bounded protocol exceptions from malformed direct-TCP traffic but observed " + exception.GetType().FullName + ".");
                                }
                            }
                        })
                });
        }

        private static ulong AuthenticateSession(OpenCifsServerHost host)
        {
            OpenCifsServerSessionSetupResult challengeResult = host.HandleSessionSetup(0, CreateInitialSessionSetupRequest(TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultUserDomain));
            OpenCifsServerSessionSetupResult successResult = host.HandleSessionSetup(
                challengeResult.SessionId,
                CreateAuthenticateSessionSetupRequest(TestEnvironmentDefaults.DefaultUserName, TestEnvironmentDefaults.DefaultUserDomain, TestEnvironmentDefaults.DefaultPassword, challengeResult));

            TestAssertions.Equal(NtStatus.Success, successResult.Status, "Expected authentication to succeed before session-scoped operations.");
            return successResult.SessionId;
        }

        private static (ulong SessionId, uint TreeId) AuthenticateAndConnectTree(OpenCifsServerHost host)
        {
            ulong sessionId = AuthenticateSession(host);

            OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(
                sessionId,
                new Smb2TreeConnectRequest
                {
                    Path = "\\\\" + TestEnvironmentDefaults.DefaultServerName + "\\" + TestEnvironmentDefaults.DefaultShareName
                });
            TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected tree connect to succeed before file operations.");
            return (sessionId, treeConnectResult.TreeId);
        }

        private static (ulong SessionId, byte[] SigningKey) AuthenticateSessionAndGetSigningKey(
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
            return (successResult.SessionId, CreateExpectedSigningKey(responseSet.SessionBaseKey, expectedDialect));
        }

        private static Smb2NegotiateResponse NegotiateDialect(OpenCifsServerHost host, SmbDialect[] dialects, SmbDialect expectedDialect, Guid? clientGuid = null, Smb2GlobalCapabilities capabilities = Smb2GlobalCapabilities.None)
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

        private static byte[] CreateSignedPacketBytes(Smb2Header header, byte[] payload, byte[] signingKey, SmbDialect dialect = SmbDialect.Smb2002)
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

        private static byte[] CreateExpectedSigningKey(byte[] sessionKey, SmbDialect dialect)
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

        private static byte[] CreateExpectedSpnegoMechanismListMic(IReadOnlyList<string> mechanismTypes, NtlmNegotiateFlags flags, byte[] sessionKey)
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

        private static byte[] CreateExpectedNtlmSigningKey(NtlmNegotiateFlags flags, byte[] sessionKey, bool serverToClient)
        {
            string direction = serverToClient ? "server-to-client" : "client-to-server";
            byte[] suffix = Encoding.ASCII.GetBytes("session key to " + direction + " signing key magic constant\0");
            byte[] material = new byte[sessionKey.Length + suffix.Length];
            Buffer.BlockCopy(sessionKey, 0, material, 0, sessionKey.Length);
            Buffer.BlockCopy(suffix, 0, material, sessionKey.Length, suffix.Length);
            return MD5.HashData(material);
        }

        private static byte[] CreateExpectedNtlmSealingKey(NtlmNegotiateFlags flags, byte[] sessionKey, bool serverToClient)
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

        private static byte[] EncodeSpnegoMechanismTypeList(IReadOnlyList<string> mechanismTypes)
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

        private static byte[] ExtractSessionBaseKey(string userName, string userDomain, string password, OpenCifsServerSessionSetupResult challengeResult)
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

        private static SigningAlgorithmId GetSigningAlgorithmForDialect(SmbDialect dialect)
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

        private static Smb2CreateRequest CreateFileCreateRequest(
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

        private static Smb2SessionSetupRequest CreateInitialSessionSetupRequest(string userName, string userDomain)
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

        private static Smb2SessionSetupRequest CreateStandardInitialSessionSetupRequest(string userName, string userDomain)
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

        private static Smb2SessionSetupRequest CreateAuthenticateSessionSetupRequest(string userName, string userDomain, string password, OpenCifsServerSessionSetupResult challengeResult)
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

        private static Smb2SessionSetupRequest CreateStandardAuthenticateSessionSetupRequest(string userName, string userDomain, string password, OpenCifsServerSessionSetupResult challengeResult)
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

        private static NtlmAvPair[] CloneAvPairs(IReadOnlyList<NtlmAvPair> avPairs)
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

        private static bool TryGetChallengeTimestamp(IReadOnlyList<NtlmAvPair> avPairs, out ulong timestamp)
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

        private static Smb2Header CreateRequestHeader(Smb2Command command, ulong messageId, ushort creditRequest = 1, ushort creditCharge = 0, Smb2HeaderFlags flags = Smb2HeaderFlags.None, ulong sessionId = 0, uint treeId = 0, ulong asyncId = 0)
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

        private static IReadOnlyList<(string Name, byte[] Payload)> BuildDirectTcpMutationRequestBaselines()
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

            return new List<(string Name, byte[] Payload)>
            {
                ("Smb2NegotiatePacket", smb2Packet.ToByteArray()),
                ("Smb1MultiProtocolNegotiate", smb1Request.ToByteArray())
            };
        }

        private static byte[] Hex(string value)
        {
            return Convert.FromHexString(value.Replace(" ", string.Empty));
        }

        private static int AllocateTcpPort()
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

        private static async Task<(CancellationTokenSource CancellationTokenSource, Task ServerTask)> StartDirectTcpServerAsync(int port, CancellationToken cancellationToken)
        {
            return await StartDirectTcpServerAsync(port, _ => { }, cancellationToken).ConfigureAwait(false);
        }

        private static async Task<(CancellationTokenSource CancellationTokenSource, Task ServerTask)> StartDirectTcpServerAsync(
            int port,
            bool requireEncryptionForSmb3,
            CancellationToken cancellationToken)
        {
            return await StartDirectTcpServerAsync(
                port,
                requireEncryptionForSmb3,
                _ => { },
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<(CancellationTokenSource CancellationTokenSource, Task ServerTask)> StartDirectTcpServerAsync(
            int port,
            Action<Exception> exceptionHandler,
            CancellationToken cancellationToken)
        {
            return await StartDirectTcpServerAsync(
                port,
                requireEncryptionForSmb3: true,
                exceptionHandler,
                cancellationToken).ConfigureAwait(false);
        }

        private static async Task<(CancellationTokenSource CancellationTokenSource, Task ServerTask)> StartDirectTcpServerAsync(
            int port,
            bool requireEncryptionForSmb3,
            Action<Exception> exceptionHandler,
            CancellationToken cancellationToken)
        {
            DirectTcpPortReservation reservation = GetDirectTcpPortReservation(port);
            OpenCifsDirectTcpServer server = new OpenCifsDirectTcpServer(new OpenCifsServerOptions
            {
                ServerName = "127.0.0.1",
                BindAddress = "127.0.0.1",
                BindPort = port,
                RequireEncryptionForSmb3 = requireEncryptionForSmb3
            }, exceptionHandler: exceptionHandler);
            CancellationTokenSource serverCancellationTokenSource = new CancellationTokenSource();
            Task serverTask = server.RunAsync(serverCancellationTokenSource.Token);

            try
            {
                await WaitForTcpListenerStateAsync(reservation.Port, shouldAcceptConnections: true, cancellationToken).ConfigureAwait(false);
                return (serverCancellationTokenSource, serverTask);
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

        private static async Task StopDirectTcpServerAsync(CancellationTokenSource serverCancellationTokenSource, Task serverTask)
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

        private static DirectTcpPortReservation GetDirectTcpPortReservation(int port)
        {
            DirectTcpPortReservation? reservation = _CurrentDirectTcpPortReservation.Value;

            if (reservation == null || reservation.Port != port)
            {
                throw new InvalidOperationException("Expected a reserved direct-TCP test port before starting the server.");
            }

            return reservation;
        }

        private static void ReleaseDirectTcpPortReservation()
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

        private static async Task WriteDirectTcpFrameAsync(NetworkStream stream, byte[] payload, CancellationToken cancellationToken)
        {
            byte[] headerBytes = new DirectTcpFrameHeader
            {
                Length = payload.Length
            }.ToByteArray();
            await stream.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
            await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        private static async Task<byte[]> ReadDirectTcpFramePayloadAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[]? payload = await TryReadDirectTcpFramePayloadAsync(stream, cancellationToken).ConfigureAwait(false);

            if (payload == null)
            {
                throw new InvalidOperationException("Expected a Direct-TCP response frame but the connection closed instead.");
            }

            return payload;
        }

        private static async Task<byte[]?> TryReadDirectTcpFramePayloadAsync(NetworkStream stream, CancellationToken cancellationToken)
        {
            byte[] headerBytes = new byte[DirectTcpFrameHeader.Size];
            int headerRead = await ReadExactOrDetectCloseAsync(stream, headerBytes, cancellationToken).ConfigureAwait(false);

            if (headerRead == 0)
            {
                return null;
            }

            DirectTcpFrameHeader header = DirectTcpFrameHeader.ReadFrom(headerBytes);
            byte[] payload = new byte[header.Length];
            int payloadRead = await ReadExactOrDetectCloseAsync(stream, payload, cancellationToken).ConfigureAwait(false);

            if (payloadRead == 0)
            {
                throw new InvalidOperationException("The Direct-TCP connection closed before the response payload was received.");
            }

            return payload;
        }

        private static async Task AssertNegotiatesDirectTcpRequestAsync(int port, byte[] requestPayload, CancellationToken cancellationToken)
        {
            using TcpClient tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, port, cancellationToken).ConfigureAwait(false);
            using NetworkStream stream = tcpClient.GetStream();
            await WriteDirectTcpFrameAsync(stream, requestPayload, cancellationToken).ConfigureAwait(false);

            byte[] responsePayload = await ReadDirectTcpFramePayloadAsync(stream, cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responsePayload);
            TestAssertions.Equal(1, responsePacket.Entries.Count, "Expected a single negotiate response entry.");
            TestAssertions.Equal(Smb2Command.Negotiate, responsePacket.Entries[0].Header.Command, "Expected a negotiate response command.");
            TestAssertions.Equal(NtStatus.Success, responsePacket.Entries[0].Header.Status, "Expected the negotiate response status to be success.");

            byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimResponsePayload(
                Smb2Command.Negotiate,
                responsePacket.Entries[0].Payload);
            Smb2NegotiateResponse response = Smb2NegotiateResponse.ReadFrom(trimmedPayload);
            Smb2NegotiateResponseValidator.Validate(response);
            TestAssertions.Equal(SmbDialect.Smb21, response.Dialect, "Expected the direct-TCP negotiate response to resolve to SMB 2.1.");
        }

        private static async Task<byte[]?> SendMalformedDirectTcpFrameAsync(int port, byte[] requestPayload, CancellationToken cancellationToken)
        {
            using TcpClient tcpClient = new TcpClient();
            await tcpClient.ConnectAsync(IPAddress.Loopback, port, cancellationToken).ConfigureAwait(false);
            using NetworkStream stream = tcpClient.GetStream();

            if (requestPayload.Length == 0)
            {
                byte[] zeroLengthHeaderBytes = new byte[DirectTcpFrameHeader.Size];
                await stream.WriteAsync(zeroLengthHeaderBytes, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            else
            {
                await WriteDirectTcpFrameAsync(stream, requestPayload, cancellationToken).ConfigureAwait(false);
            }

            using CancellationTokenSource timeoutTokenSource = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            using CancellationTokenSource linkedTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutTokenSource.Token);

            try
            {
                return await TryReadDirectTcpFramePayloadAsync(stream, linkedTokenSource.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (timeoutTokenSource.IsCancellationRequested)
            {
                return null;
            }
            catch (InvalidOperationException)
            {
                return null;
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (OverflowException)
            {
                return null;
            }
            catch (ProtocolEncodingException)
            {
                return null;
            }
        }

        private static async Task<int> ReadExactOrDetectCloseAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
        {
            int offset = 0;

            while (offset < buffer.Length)
            {
                int count = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken).ConfigureAwait(false);

                if (count == 0)
                {
                    if (offset == 0)
                    {
                        return 0;
                    }

                    throw new InvalidOperationException("The Direct-TCP connection closed before the frame completed.");
                }

                offset += count;
            }

            return offset;
        }

        private static async Task WaitForTcpListenerStateAsync(int port, bool shouldAcceptConnections, CancellationToken cancellationToken)
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

                    if (shouldAcceptConnections)
                    {
                        return;
                    }
                }
                catch (SocketException)
                {
                    if (!shouldAcceptConnections)
                    {
                        return;
                    }
                }
                catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    if (!shouldAcceptConnections)
                    {
                        return;
                    }
                }

                await Task.Delay(100, cancellationToken).ConfigureAwait(false);
            }

            throw new InvalidOperationException(
                shouldAcceptConnections
                    ? "Timed out waiting for the managed server listener to accept direct-TCP probe connections."
                    : "Timed out waiting for the managed server listener to stop accepting direct-TCP probe connections.");
        }

        private static void DeleteDirectoryForcefully(string rootPath)
        {
            TestPathUtilities.DeleteDirectoryForcefully(rootPath);
        }

        private static (int ExitCode, string StandardOutput, string StandardError) RunSampleProgram(params string[] args)
        {
            lock (_ConsoleCaptureLock)
            {
                TextWriter originalOut = Console.Out;
                TextWriter originalError = Console.Error;
                using StringWriter capturedOut = new StringWriter();
                using StringWriter capturedError = new StringWriter();

                try
                {
                    Console.SetOut(capturedOut);
                    Console.SetError(capturedError);
                    int exitCode = Program.Main(args);
                    return (exitCode, capturedOut.ToString(), capturedError.ToString());
                }
                finally
                {
                    Console.SetOut(originalOut);
                    Console.SetError(originalError);
                }
            }
        }

        private static readonly object _ConsoleCaptureLock = new object();
    }
}
