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
    internal static class ServerDefaultsShareAndBuilderCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
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
            };
        }
    }
}
