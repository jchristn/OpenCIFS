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
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal static class ClientIoctlSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Client.Ioctl",
                displayName: "Client IOCTL handling",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Client.Ioctl",
                        caseId: "ClientBuildsIoctlRequestsAndAcceptsSuccessfulResponses",
                        displayName: "Client builds secure-negotiate, open, and wildcard SMB2 IOCTL requests and accepts successful responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();
                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 710,
                                    VolatileFileId = 711,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            Smb2IoctlRequest openRequest = session.CreateIoctlRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                (uint)FsctlCode.SrvEnumerateSnapshots,
                                inputBuffer: new byte[] { 0x10, 0x20 },
                                maxOutputResponse: 1024);
                            Smb2IoctlRequestValidator.Validate(openRequest);
                            TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, openRequest.CtlCode, "Unexpected client IOCTL control code.");
                            TestAssertions.Equal(Smb2IoctlFlags.IsFsctl, openRequest.Flags, "Unexpected client IOCTL flags.");
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x20 }, openRequest.InputBuffer, "Unexpected client IOCTL input buffer.");

                            byte[] openOutput = session.ApplyIoctlResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = openState.PersistentFileId,
                                    VolatileFileId = openState.VolatileFileId,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new byte[] { 0x41, 0x42 },
                                    Flags = 0
                                });
                            TestAssertions.SequenceEqual(new byte[] { 0x41, 0x42 }, openOutput, "Unexpected client IOCTL output buffer.");

                            Smb2IoctlRequest connectionRequest = session.CreateConnectionIoctlRequest(
                                (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                maxOutputResponse: 2048);
                            Smb2IoctlRequestValidator.Validate(connectionRequest);
                            TestAssertions.Equal(UInt64.MaxValue, connectionRequest.PersistentFileId, "Expected wildcard IOCTL persistent file identifier.");
                            TestAssertions.Equal(UInt64.MaxValue, connectionRequest.VolatileFileId, "Expected wildcard IOCTL volatile file identifier.");

                            byte[] connectionOutput = session.ApplyConnectionIoctlResult(
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = UInt64.MaxValue,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new byte[] { 0x99 },
                                    Flags = 0
                                });
                            TestAssertions.SequenceEqual(new byte[] { 0x99 }, connectionOutput, "Unexpected client wildcard IOCTL output buffer.");

                            OpenCifsClientSession secureNegotiateSession = CreateAuthenticatedClient(SmbDialect.Smb302);
                            Smb2IoctlRequest validateNegotiateRequest = secureNegotiateSession.CreateValidateNegotiateInfoRequest(maxOutputResponse: 256);
                            ValidateNegotiateInfoRequest parsedValidateRequest = ValidateNegotiateInfoRequest.ReadFrom(validateNegotiateRequest.InputBuffer);
                            TestAssertions.Equal((uint)FsctlCode.ValidateNegotiateInfo, validateNegotiateRequest.CtlCode, "Unexpected secure-negotiate FSCTL code.");
                            TestAssertions.Equal(UInt64.MaxValue, validateNegotiateRequest.PersistentFileId, "Expected secure-negotiate requests to use the wildcard persistent file identifier.");
                            TestAssertions.Equal(UInt64.MaxValue, validateNegotiateRequest.VolatileFileId, "Expected secure-negotiate requests to use the wildcard volatile file identifier.");
                            TestAssertions.Equal(4, parsedValidateRequest.Dialects.Length, "Expected the secure-negotiate request to preserve the original offered dialect list.");
                            TestAssertions.Equal(SmbDialect.Smb302, parsedValidateRequest.Dialects[3], "Expected the secure-negotiate request to preserve SMB 3.0.2 in the offered dialect list.");
                            TestAssertions.Equal(secureNegotiateSession.ClientGuid, parsedValidateRequest.ClientGuid, "Expected the secure-negotiate request to preserve the original client GUID.");
                            TestAssertions.Equal(
                                Smb2GlobalCapabilities.Dfs | Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing,
                                parsedValidateRequest.Capabilities,
                                "Expected the secure-negotiate request to preserve the original client capability advertisement.");

                            ValidateNegotiateInfoResponse validateNegotiateResponse = secureNegotiateSession.ApplyValidateNegotiateInfoResult(
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = UInt64.MaxValue,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new ValidateNegotiateInfoResponse
                                    {
                                        Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                        ServerGuid = secureNegotiateSession.ServerGuid!.Value,
                                        SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                        Dialect = SmbDialect.Smb302
                                    }.ToByteArray(),
                                    Flags = 0
                                });
                            TestAssertions.True(secureNegotiateSession.IsSecureNegotiateValidated, "Expected successful secure-negotiate validation to mark the authenticated SMB3 session as validated.");
                            TestAssertions.Equal(SmbDialect.Smb302, validateNegotiateResponse.Dialect, "Expected secure-negotiate validation to preserve the negotiated SMB3 dialect.");

                            Smb2IoctlRequest enumerateSnapshotsRequest = session.CreateEnumerateSnapshotsRequest(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                maxOutputResponse: 256);
                            TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, enumerateSnapshotsRequest.CtlCode, "Unexpected snapshot-enumeration FSCTL code.");
                            SrvSnapshotArray snapshotArray = session.ApplyEnumerateSnapshotsResult(
                                openState.PersistentFileId,
                                openState.VolatileFileId,
                                NtStatus.Success,
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = openState.PersistentFileId,
                                    VolatileFileId = openState.VolatileFileId,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = new SrvSnapshotArray
                                    {
                                        NumberOfSnapshots = 0,
                                        Snapshots = Array.Empty<string>()
                                    }.ToByteArray(),
                                    Flags = 0
                                });
                            TestAssertions.Equal(0U, snapshotArray.NumberOfSnapshots, "Unexpected client-observed snapshot count.");
                            TestAssertions.Equal(0, snapshotArray.Snapshots.Length, "Expected the bounded snapshot enumeration slice to allow an empty snapshot list.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Ioctl",
                        caseId: "ClientRejectsIoctlRequestsForUnknownOpenAndFailedStatus",
                        displayName: "Client rejects invalid secure-negotiate, unknown-open, and failed SMB2 IOCTL responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedTreeClient();

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.CreateIoctlRequest(1, 2, (uint)FsctlCode.SrvEnumerateSnapshots),
                                "Open-scoped IOCTL requests should fail for an unknown open.");

                            OpenCifsClientSession negotiatedSession = CreateNegotiatedClient();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.CreateConnectionIoctlRequest((uint)FsctlCode.QueryNetworkInterfaceInfo),
                                "Wildcard IOCTL requests should require an authenticated session.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => negotiatedSession.CreateValidateNegotiateInfoRequest(),
                                "Secure-negotiate IOCTL requests should require an authenticated session.");

                            OpenState openState = session.ApplyCreateResult(
                                42,
                                "notes.txt",
                                NtStatus.Success,
                                new Smb2CreateResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    Flags = 0,
                                    CreateAction = Smb2CreateAction.Opened,
                                    FileAttributes = FileAttributes.Normal,
                                    PersistentFileId = 720,
                                    VolatileFileId = 721,
                                    CreateContexts = Array.Empty<byte>()
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyIoctlResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    NtStatus.NotSupported,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = Array.Empty<byte>(),
                                        Flags = 0
                                    }),
                                "Failed open-scoped IOCTL results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyConnectionIoctlResult(
                                    NtStatus.NotSupported,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = Array.Empty<byte>(),
                                        Flags = 0
                                    }),
                                "Failed wildcard IOCTL results should throw.");

                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.ApplyEnumerateSnapshotsResult(
                                    openState.PersistentFileId,
                                    openState.VolatileFileId,
                                    NtStatus.Success,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots + 1,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = new SrvSnapshotArray
                                        {
                                            NumberOfSnapshots = 0,
                                            Snapshots = Array.Empty<string>()
                                        }.ToByteArray(),
                                        Flags = 0
                                    }),
                                "Snapshot-enumeration results should reject unexpected FSCTL codes.");

                            OpenCifsClientSession secureNegotiateSession = CreateAuthenticatedClient(SmbDialect.Smb302);
                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => secureNegotiateSession.ApplyValidateNegotiateInfoResult(
                                    NtStatus.Success,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.ValidateNegotiateInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = new ValidateNegotiateInfoResponse
                                        {
                                            Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Leasing | Smb2GlobalCapabilities.Encryption,
                                            ServerGuid = Guid.Parse("8FCA17D4-78F4-4967-8686-2C278149C391"),
                                            SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                            Dialect = SmbDialect.Smb302
                                        }.ToByteArray(),
                                        Flags = 0
                                    }),
                                "Secure-negotiate results should reject a mismatched server GUID.");

                            TestAssertions.Throws<OpenCifsClientProtocolException>(
                                () => secureNegotiateSession.ApplyValidateNegotiateInfoResult(
                                    NtStatus.Success,
                                    new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = new byte[] { 0x01 },
                                        Flags = 0
                                    }),
                                "Secure-negotiate results should reject unexpected FSCTL codes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Client.Ioctl",
                        caseId: "ClientBuildsDfsGetReferralsExRequestsAndPreservesConfiguredSiteNameOnSmb3Lanes",
                        displayName: "Client builds DFS_GET_REFERRALS_EX requests and preserves the configured site name on SMB3 lanes",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsClientSession session = CreateAuthenticatedClient(SmbDialect.Smb302);
                            OpenCifsClientTreeHandle ipcTreeHandle = new OpenCifsClientTreeHandle(
                                Guid.Parse("C92E4462-7F95-49E8-BEFE-FE1115168F33"),
                                1,
                                "IPC$",
                                73,
                                Smb2ShareFlags.None);
                            Smb2IoctlRequest? capturedRequest = null;
                            OpenCifsClientAdministrationService administrationService = new OpenCifsClientAdministrationService(
                                new OpenCifsClientOptions
                                {
                                    ServerName = "127.0.0.1",
                                    DfsSiteName = "Default-First-Site-Name"
                                },
                                () => session,
                                () =>
                                {
                                    if (!session.IsAuthenticated)
                                    {
                                        throw new InvalidOperationException("Expected an authenticated session for DFS referral requests.");
                                    }
                                },
                                _ => { },
                                cancellationToken => Task.FromResult(ipcTreeHandle),
                                (_, _, _) => throw new InvalidOperationException("DFS referral requests should not open named pipes."),
                                (_, _) => Task.CompletedTask,
                                (_, _) => Task.CompletedTask,
                                (requestHeader, requestPayload, _) =>
                                {
                                    string matchedPath = @"\127.0.0.1\public\team";
                                    capturedRequest = Smb2IoctlRequest.ReadFrom(requestPayload);
                                    DfsReferralRequestEx parsedRequest = DfsReferralRequestEx.ReadFrom(capturedRequest.InputBuffer);
                                    TestAssertions.Equal((uint)FsctlCode.DfsGetReferralsEx, capturedRequest.CtlCode, "Expected SMB3 DFS resolution to use FSCTL_DFS_GET_REFERRALS_EX.");
                                    TestAssertions.True(parsedRequest.IncludeSiteName, "Expected DFS_GET_REFERRALS_EX requests to carry the configured site name.");
                                    TestAssertions.Equal("Default-First-Site-Name", parsedRequest.SiteName, "Unexpected DFS_GET_REFERRALS_EX site name.");
                                    TestAssertions.Equal(@"\127.0.0.1\public\team\report.txt", parsedRequest.RequestFileName, "Unexpected DFS_GET_REFERRALS_EX request path.");

                                    DfsReferralResponse referralResponse = new DfsReferralResponse
                                    {
                                        PathConsumed = checked((ushort)(matchedPath.Length * 2)),
                                        HeaderFlags = DfsReferralHeaderFlags.StorageServers
                                    };
                                    referralResponse.EntriesV3.Add(new DfsReferralEntryV3
                                    {
                                        VersionNumber = 4,
                                        IsRootTarget = false,
                                        ReferralEntryFlags = DfsReferralEntryFlags.None,
                                        TimeToLive = 600,
                                        DfsPath = matchedPath,
                                        DfsAlternatePath = matchedPath,
                                        NetworkAddress = @"\127.0.0.1\public\resolved\team",
                                        ServiceSiteGuid = new byte[16]
                                    });
                                    Smb2IoctlResponse response = new Smb2IoctlResponse
                                    {
                                        CtlCode = (uint)FsctlCode.DfsGetReferralsEx,
                                        PersistentFileId = UInt64.MaxValue,
                                        VolatileFileId = UInt64.MaxValue,
                                        InputBuffer = Array.Empty<byte>(),
                                        OutputBuffer = referralResponse.ToByteArray(),
                                        Flags = 0
                                    };
                                    return Task.FromResult(new OpenCifsClientRequestResponse(
                                        CreateResponseHeader(requestHeader),
                                        response.ToByteArray()));
                                });

                            OpenCifsDfsReferral[] referrals = await administrationService.GetDfsReferralsAsync(
                                "\\\\127.0.0.1\\public\\team\\report.txt",
                                token).ConfigureAwait(false);
                            TestAssertions.Equal(1, referrals.Length, "Expected a single returned DFS referral.");
                            TestAssertions.Equal(@"\127.0.0.1\public\team", referrals[0].ReferralPath, "Expected the V3/V4 referral path to be preserved.");
                            TestAssertions.Equal("127.0.0.1", referrals[0].TargetServerName, "Expected the V3/V4 referral target server to be parsed.");
                            TestAssertions.Equal("public", referrals[0].TargetShareName, "Expected the V3/V4 referral target share to be parsed.");
                            TestAssertions.Equal("resolved\\team", referrals[0].TargetPath, "Expected the V3/V4 referral target relative path to be parsed.");
                            TestAssertions.Equal((uint)FsctlCode.DfsGetReferralsEx, capturedRequest!.CtlCode, "Expected the captured DFS request to remain an EX request.");
                        })
                });
        }
    }
}
