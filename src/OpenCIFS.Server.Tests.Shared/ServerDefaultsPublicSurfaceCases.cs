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
    internal static class ServerDefaultsPublicSurfaceCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
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
                            TestCaseVariantCoverage.AssertBalancedVariants(ServerTestSuites.All, "Server");
                            return Task.CompletedTask;
                        })
            };
        }
    }
}
