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
    internal static class ServerIoctlSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
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
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

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
                        caseId: "ServerHandlesLegacyV2AndExV4DfsReferralEntriesOnSupportedIoctlLanes",
                        displayName: "Server handles legacy V2 and DFS_GET_REFERRALS_EX V4 referral entries on the supported IOCTL lanes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerIoctlDfs_" + Guid.NewGuid().ToString("N"));
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
                                    NamespacePath = "/team",
                                    TargetServerName = "files-target",
                                    TargetShareName = "data",
                                    TargetPath = "/team",
                                    TimeToLiveSeconds = 600
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
                                {
                                    ClientGuid = Guid.Parse("B6BB414A-1B43-4BE6-887D-BB9FE569834A"),
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Encryption,
                                    Dialects = new[] { SmbDialect.Smb302 }
                                };
                                host.HandleNegotiate(negotiateRequest);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                string requestPath = "\\\\" + TestEnvironmentDefaults.DefaultServerName + "\\" + TestEnvironmentDefaults.DefaultShareName + "\\team\\report.txt";

                                OpenCifsServerOperationResult<Smb2IoctlResponse> legacyResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.DfsGetReferrals,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new DfsReferralRequest
                                        {
                                            MaxReferralLevel = 2,
                                            RequestPath = requestPath
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, legacyResult.Status, "Expected bounded legacy DFS referral IOCTL requests to succeed.");
                                DfsReferralResponse legacyResponse = DfsReferralResponse.ReadFrom(legacyResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, legacyResponse.EntriesV2.Count, "Expected bounded legacy DFS referral IOCTL responses to continue emitting V2 entries.");
                                TestAssertions.Equal(0, legacyResponse.EntriesV3.Count, "Expected bounded legacy DFS referral IOCTL responses to avoid V3/V4 entries.");
                                TestAssertions.Equal(@"\files-target\data\team", legacyResponse.EntriesV2[0].NetworkAddress, "Unexpected bounded legacy DFS target network address.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> exResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.DfsGetReferralsEx,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new DfsReferralRequestEx
                                        {
                                            MaxReferralLevel = 4,
                                            IncludeSiteName = true,
                                            PathConsumed = 0,
                                            RequestFileName = requestPath,
                                            SiteName = "Default-First-Site-Name"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, exResult.Status, "Expected bounded DFS_GET_REFERRALS_EX IOCTL requests to succeed on SMB3 lanes.");
                                DfsReferralResponse exResponse = DfsReferralResponse.ReadFrom(exResult.Response.OutputBuffer);
                                TestAssertions.Equal(0, exResponse.EntriesV2.Count, "Expected bounded DFS_GET_REFERRALS_EX responses to emit only V3/V4 entries.");
                                TestAssertions.Equal(1, exResponse.EntriesV3.Count, "Expected bounded DFS_GET_REFERRALS_EX responses to emit a V3/V4 referral entry.");
                                TestAssertions.Equal((ushort)4, exResponse.EntriesV3[0].VersionNumber, "Expected bounded DFS_GET_REFERRALS_EX responses to emit V4 referral entries.");
                                TestAssertions.Equal(DfsReferralEntryFlags.None, exResponse.EntriesV3[0].ReferralEntryFlags, "Expected bounded DFS_GET_REFERRALS_EX responses to avoid unsupported NameList referral flags.");
                                TestAssertions.Equal(@"\files-target\data\team", exResponse.EntriesV3[0].NetworkAddress, "Unexpected bounded DFS_GET_REFERRALS_EX target network address.");
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
                        caseId: "ServerHandlesBoundedNameListDfsReferralEntriesOnDfsGetReferralsExAndRejectsLegacyLane",
                        displayName: "Server handles bounded NameList DFS referral entries on DFS_GET_REFERRALS_EX and rejects the legacy lane",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerIoctlDfsNameList_" + Guid.NewGuid().ToString("N"));
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
                                    NamespacePath = "/domain",
                                    IsNameListReferral = true,
                                    SpecialName = "CONTOSO",
                                    ExpandedNames = new string[]
                                    {
                                        "\\\\dc1.contoso.test",
                                        "\\\\dc2.contoso.test"
                                    },
                                    TimeToLiveSeconds = 600
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
                                {
                                    ClientGuid = Guid.Parse("FCFB535C-6C82-4B75-A74D-8D8A9EEA492B"),
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Encryption,
                                    Dialects = new[] { SmbDialect.Smb302 }
                                };
                                host.HandleNegotiate(negotiateRequest);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                string requestPath = "\\\\" + TestEnvironmentDefaults.DefaultServerName + "\\" + TestEnvironmentDefaults.DefaultShareName + "\\domain";

                                OpenCifsServerOperationResult<Smb2IoctlResponse> legacyResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.DfsGetReferrals,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new DfsReferralRequest
                                        {
                                            MaxReferralLevel = 2,
                                            RequestPath = requestPath
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, legacyResult.Status, "Expected the bounded NameList DFS lane to require DFS_GET_REFERRALS_EX instead of the legacy V2 response path.");

                                OpenCifsServerOperationResult<Smb2IoctlResponse> exResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.DfsGetReferralsEx,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new DfsReferralRequestEx
                                        {
                                            MaxReferralLevel = 4,
                                            IncludeSiteName = true,
                                            PathConsumed = 0,
                                            RequestFileName = requestPath,
                                            SiteName = "Default-First-Site-Name"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, exResult.Status, "Expected bounded NameList DFS referrals to succeed on DFS_GET_REFERRALS_EX.");
                                DfsReferralResponse exResponse = DfsReferralResponse.ReadFrom(exResult.Response.OutputBuffer);
                                TestAssertions.Equal(DfsReferralHeaderFlags.ReferralServers, exResponse.HeaderFlags, "Expected NameList DFS referrals to advertise referral servers instead of final storage servers.");
                                TestAssertions.Equal(0, exResponse.EntriesV2.Count, "Expected NameList DFS referrals to stay off the legacy V2 response shape.");
                                TestAssertions.Equal(1, exResponse.EntriesV3.Count, "Expected a single NameList DFS referral entry.");
                                TestAssertions.Equal((ushort)4, exResponse.EntriesV3[0].VersionNumber, "Expected bounded NameList DFS referrals on SMB3 to use the V4 response shape.");
                                TestAssertions.Equal(DfsReferralEntryFlags.NameListReferral, exResponse.EntriesV3[0].ReferralEntryFlags, "Expected the returned DFS referral entry to preserve the NameList flag.");
                                TestAssertions.Equal("CONTOSO", exResponse.EntriesV3[0].SpecialName, "Unexpected NameList DFS special name.");
                                TestAssertions.Equal(2, exResponse.EntriesV3[0].ExpandedNames.Length, "Expected the NameList DFS referral entry to preserve both expanded names.");
                                TestAssertions.Equal("\\\\dc1.contoso.test", exResponse.EntriesV3[0].ExpandedNames[0], "Unexpected first NameList DFS expanded name.");
                                TestAssertions.Equal("\\\\dc2.contoso.test", exResponse.EntriesV3[0].ExpandedNames[1], "Unexpected second NameList DFS expanded name.");
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
                        caseId: "ServerHandlesBoundedDfsGetReferralsExSiteAwareTargetOrdering",
                        displayName: "Server handles bounded DFS_GET_REFERRALS_EX site-aware target ordering by the requested site name",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerIoctlDfsSite_" + Guid.NewGuid().ToString("N"));
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
                                    NamespacePath = "/team",
                                    SiteName = "Branch",
                                    TargetServerName = "files-branch",
                                    TargetShareName = "data",
                                    TargetPath = "/team",
                                    TimeToLiveSeconds = 600
                                });
                                builder.AddDfsReferral(new OpenCifsServerDfsReferral
                                {
                                    NamespaceShareName = TestEnvironmentDefaults.DefaultShareName,
                                    NamespacePath = "/team",
                                    SiteName = "HQ",
                                    TargetServerName = "files-hq",
                                    TargetShareName = "data",
                                    TargetPath = "/team",
                                    TimeToLiveSeconds = 600
                                });

                                OpenCifsServerHost host = builder.BuildHost();
                                Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
                                {
                                    ClientGuid = Guid.Parse("9C6DEBD8-44F9-4F38-8B30-D48E8C379E0B"),
                                    SecurityMode = Smb2SecurityMode.SigningEnabled,
                                    Capabilities = Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Encryption,
                                    Dialects = new[] { SmbDialect.Smb302 }
                                };
                                host.HandleNegotiate(negotiateRequest);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                string requestPath = "\\\\" + TestEnvironmentDefaults.DefaultServerName + "\\" + TestEnvironmentDefaults.DefaultShareName + "\\team\\report.txt";

                                OpenCifsServerOperationResult<Smb2IoctlResponse> exResult = host.HandleIoctl(
                                    sessionId,
                                    treeId,
                                    new Smb2IoctlRequest
                                    {
                                        CtlCode = (uint)FsctlCode.DfsGetReferralsEx,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        MaxInputResponse = 0,
                                        MaxOutputResponse = 4096,
                                        Flags = Smb2IoctlFlags.IsFsctl,
                                        InputBuffer = new DfsReferralRequestEx
                                        {
                                            MaxReferralLevel = 4,
                                            IncludeSiteName = true,
                                            PathConsumed = 0,
                                            RequestFileName = requestPath,
                                            SiteName = "HQ"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, exResult.Status, "Expected bounded site-aware DFS_GET_REFERRALS_EX requests to succeed.");
                                DfsReferralResponse exResponse = DfsReferralResponse.ReadFrom(exResult.Response.OutputBuffer);
                                TestAssertions.Equal(2, exResponse.EntriesV3.Count, "Expected the bounded site-aware DFS response to preserve both targets.");
                                TestAssertions.Equal(@"\files-hq\data\team", exResponse.EntriesV3[0].NetworkAddress, "Expected the requested-site target to be ordered first in the EX response.");
                                TestAssertions.Equal(@"\files-branch\data\team", exResponse.EntriesV3[1].NetworkAddress, "Expected non-matching site targets to remain after the requested-site target.");
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
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

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

                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);

                                ulong sessionId = treeContext.SessionId;

                                uint treeId = treeContext.TreeId;
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
    }
}
