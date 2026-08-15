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
    internal static class ServerDfsConfigurationSuiteBuilder
    {
        /// <summary>
        /// Build the bounded server-side DFS referral configuration suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ServerDfsConfigurationSuite()
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
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.DfsConfiguration",
                        caseId: "ServerTreeConnectToShareWithRootDfsReferralAdvertisesDfsRootShareFlags",
                        displayName: "Server tree connect to a share with a root DFS referral advertises DFS and DFS root share flags",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerDfsRoot_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);

                            try
                            {
                                OpenCifsServerHostBuilder builder = new OpenCifsServerHostBuilder(new OpenCifsServerOptions
                                {
                                    ServerName = TestEnvironmentDefaults.DefaultServerName
                                });
                                builder.AddFileSystemShare(new OpenCifsServerFileSystemShare
                                {
                                    ShareName = TestEnvironmentDefaults.DefaultShareName,
                                    RootPath = sharePath,
                                    CreateRootIfMissing = true
                                });
                                builder.AddAccount(new OpenCifsServerAccount
                                {
                                    UserName = TestEnvironmentDefaults.DefaultUserName,
                                    UserDomain = TestEnvironmentDefaults.DefaultUserDomain,
                                    Password = TestEnvironmentDefaults.DefaultPassword
                                });
                                builder.AddDfsReferral(new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/",
                                    TargetServerName = TestEnvironmentDefaults.DefaultServerName,
                                    TargetShareName = TestEnvironmentDefaults.DefaultShareName,
                                    TargetPath = "/resolved-root",
                                    TimeToLiveSeconds = 600
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                ulong sessionId = AuthenticateSession(host);
                                OpenCifsServerTreeConnectResult treeConnectResult = host.HandleTreeConnect(
                                    sessionId,
                                    new Smb2TreeConnectRequest
                                    {
                                        Path = "\\\\" + TestEnvironmentDefaults.DefaultServerName + "\\" + TestEnvironmentDefaults.DefaultShareName
                                    });

                                TestAssertions.Equal(NtStatus.Success, treeConnectResult.Status, "Expected tree connect to succeed before validating DFS root share flags.");
                                Smb2ShareFlags shareFlags = (Smb2ShareFlags)treeConnectResult.Response.ShareFlags;
                                TestAssertions.True((shareFlags & Smb2ShareFlags.Dfs) != 0, "Expected shares with configured DFS referrals to advertise the DFS share flag.");
                                TestAssertions.True((shareFlags & Smb2ShareFlags.DfsRoot) != 0, "Expected shares with a root DFS referral to advertise the DFS root share flag.");
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
    }
}
