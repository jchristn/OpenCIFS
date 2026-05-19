namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class CoreDfsReferralCodecSuiteBuilder
    {
        internal static TestSuiteDescriptor DfsReferralCodecSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.DfsReferral",
                displayName: "Bounded DFS referral codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.DfsReferral",
                        caseId: "DfsReferralRequestAndResponseRoundTripBoundedV2Entries",
                        displayName: "Bounded DFS referral request and response round-trip a representative v2 entry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            DfsReferralRequest request = new DfsReferralRequest
                            {
                                MaxReferralLevel = 2,
                                RequestPath = @"\labserver\namespace\link"
                            };
                            byte[] requestBytes = request.ToByteArray();
                            DfsReferralRequest parsedRequest = DfsReferralRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal((ushort)2, parsedRequest.MaxReferralLevel, "Unexpected DFS referral request maximum level.");
                            TestAssertions.Equal(@"\labserver\namespace\link", parsedRequest.RequestPath, "Unexpected DFS referral request path.");

                            DfsReferralResponse response = new DfsReferralResponse
                            {
                                PathConsumed = (ushort)(@"\labserver\namespace".Length * 2),
                                HeaderFlags = DfsReferralHeaderFlags.StorageServers,
                                Entries = new[]
                                {
                                    new DfsReferralEntryV2
                                    {
                                        IsRootTarget = false,
                                        TimeToLive = 600,
                                        DfsPath = @"\labserver\namespace",
                                        NetworkAddress = @"\target\share"
                                    }
                                }
                            };
                            byte[] responseBytes = response.ToByteArray();
                            DfsReferralResponse parsedResponse = DfsReferralResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.PathConsumed, parsedResponse.PathConsumed, "Unexpected DFS referral response path-consumed value.");
                            TestAssertions.Equal(DfsReferralHeaderFlags.StorageServers, parsedResponse.HeaderFlags, "Unexpected DFS referral response header flags.");
                            TestAssertions.Equal(1, parsedResponse.Entries.Length, "Unexpected DFS referral entry count.");
                            TestAssertions.Equal(@"\labserver\namespace", parsedResponse.Entries[0].DfsPath, "Unexpected DFS referral entry DFS path.");
                            TestAssertions.Equal(@"\target\share", parsedResponse.Entries[0].NetworkAddress, "Unexpected DFS referral entry network address.");
                            TestAssertions.Equal((uint)600, parsedResponse.Entries[0].TimeToLive, "Unexpected DFS referral entry TTL.");
                            TestAssertions.False(parsedResponse.Entries[0].IsRootTarget, "Unexpected DFS referral root-target flag.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.DfsReferral",
                        caseId: "DfsReferralReadersRejectMalformedInputs",
                        displayName: "Bounded DFS referral readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralRequest.ReadFrom(new byte[] { 0x02, 0x00, 0x5C }),
                                "The DFS referral request reader should reject odd-length buffers.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralRequest.ReadFrom(new byte[] { 0x02, 0x00, 0x00, 0x00 }),
                                "The DFS referral request reader should reject empty paths.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralResponse.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "The DFS referral response reader should reject truncated headers.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.DfsReferral",
                        caseId: "DfsReferralResponseReadsExternalV2EntriesThatStoreStringsPastTheDeclaredEntrySize",
                        displayName: "Bounded DFS referral response tolerates external v2 entries that store strings after the fixed entry body",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] dfsPathBytes = Encoding.Unicode.GetBytes(@"\\labserver\namespace" + '\0');
                            byte[] alternatePathBytes = Encoding.Unicode.GetBytes(@"\\labserver\namespace" + '\0');
                            byte[] networkAddressBytes = Encoding.Unicode.GetBytes(@"\\target\share" + '\0');
                            LittleEndianWriter writer = new LittleEndianWriter();
                            writer.WriteUInt16((ushort)(@"\\labserver\namespace".Length * 2));
                            writer.WriteUInt16(1);
                            writer.WriteUInt32((uint)DfsReferralHeaderFlags.StorageServers);
                            writer.WriteUInt16(2);
                            writer.WriteUInt16(22);
                            writer.WriteUInt16(0);
                            writer.WriteUInt16(0);
                            writer.WriteUInt32(0);
                            writer.WriteUInt32(600);
                            writer.WriteUInt16(22);
                            writer.WriteUInt16((ushort)(22 + dfsPathBytes.Length));
                            writer.WriteUInt16((ushort)(22 + dfsPathBytes.Length + alternatePathBytes.Length));
                            writer.WriteBytes(dfsPathBytes);
                            writer.WriteBytes(alternatePathBytes);
                            writer.WriteBytes(networkAddressBytes);

                            DfsReferralResponse parsedResponse = DfsReferralResponse.ReadFrom(writer.ToArray());
                            TestAssertions.Equal(1, parsedResponse.Entries.Length, "Unexpected DFS referral entry count.");
                            TestAssertions.Equal(@"\\labserver\namespace", parsedResponse.Entries[0].DfsPath, "Unexpected DFS referral entry DFS path.");
                            TestAssertions.Equal(@"\\labserver\namespace", parsedResponse.Entries[0].DfsAlternatePath, "Unexpected DFS referral entry alternate DFS path.");
                            TestAssertions.Equal(@"\\target\share", parsedResponse.Entries[0].NetworkAddress, "Unexpected DFS referral entry network address.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Dfs",
                        caseId: "DfsReferralEntryV3RoundTripsPathConsumerLayoutAndPreservesV4VersionAndTargetSetBoundaryFlag",
                        displayName: "Bounded DFS referral V3 entry round-trips path-consumer layout and preserves V4 version and TargetSetBoundary flag",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] siteGuid = new byte[]
                            {
                                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
                            };

                            DfsReferralResponse response = new DfsReferralResponse
                            {
                                PathConsumed = (ushort)("\\\\dfs.contoso.test\\share".Length * 2),
                                HeaderFlags = DfsReferralHeaderFlags.StorageServers
                            };

                            DfsReferralEntryV3 entry = new DfsReferralEntryV3
                            {
                                VersionNumber = 4,
                                IsRootTarget = true,
                                ReferralEntryFlags = DfsReferralEntryFlags.TargetSetBoundary,
                                TimeToLive = 600,
                                DfsPath = "\\\\dfs.contoso.test\\share",
                                DfsAlternatePath = "\\\\dfs.contoso.test\\share",
                                NetworkAddress = "\\\\fileserver.contoso.test\\share",
                                ServiceSiteGuid = siteGuid
                            };
                            response.EntriesV3.Add(entry);

                            byte[] responseBytes = response.ToByteArray();
                            DfsReferralResponse parsed = DfsReferralResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(0, parsed.EntriesV2.Count, "Unexpected DFS V2 entries on a V3/V4 response.");
                            TestAssertions.Equal(1, parsed.EntriesV3.Count, "Expected exactly one DFS V3/V4 entry.");
                            DfsReferralEntryV3 parsedEntry = parsed.EntriesV3[0];
                            TestAssertions.Equal((ushort)4, parsedEntry.VersionNumber, "Unexpected DFS entry VersionNumber.");
                            TestAssertions.Equal(entry.DfsPath, parsedEntry.DfsPath, "Unexpected DFS entry DfsPath.");
                            TestAssertions.Equal(entry.NetworkAddress, parsedEntry.NetworkAddress, "Unexpected DFS entry NetworkAddress.");
                            TestAssertions.Equal(entry.TimeToLive, parsedEntry.TimeToLive, "Unexpected DFS entry TimeToLive.");
                            TestAssertions.True(parsedEntry.IsRootTarget, "Unexpected DFS entry IsRootTarget.");
                            TestAssertions.Equal(DfsReferralEntryFlags.TargetSetBoundary, parsedEntry.ReferralEntryFlags, "Unexpected DFS entry ReferralEntryFlags.");
                            TestAssertions.SequenceEqual(siteGuid, parsedEntry.ServiceSiteGuid, "Unexpected DFS entry ServiceSiteGuid.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Dfs",
                        caseId: "DfsReferralEntryV3RoundTripsNameListLayoutAndPreservesExpandedNames",
                        displayName: "Bounded DFS referral V3 entry round-trips the NameList layout and preserves expanded names",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            DfsReferralResponse response = new DfsReferralResponse
                            {
                                PathConsumed = (ushort)("\\\\contoso.test".Length * 2),
                                HeaderFlags = DfsReferralHeaderFlags.ReferralServers
                            };

                            DfsReferralEntryV3 entry = new DfsReferralEntryV3
                            {
                                VersionNumber = 3,
                                IsRootTarget = false,
                                ReferralEntryFlags = DfsReferralEntryFlags.NameListReferral,
                                TimeToLive = 900,
                                SpecialName = "\\\\contoso.test",
                                ExpandedNames = new[]
                                {
                                    "\\\\dc1.contoso.test",
                                    "\\\\dc2.contoso.test"
                                }
                            };
                            response.EntriesV3.Add(entry);

                            byte[] responseBytes = response.ToByteArray();
                            DfsReferralResponse parsed = DfsReferralResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(1, parsed.EntriesV3.Count, "Expected exactly one DFS NameList entry.");
                            DfsReferralEntryV3 parsedEntry = parsed.EntriesV3[0];
                            TestAssertions.Equal(DfsReferralEntryFlags.NameListReferral, parsedEntry.ReferralEntryFlags, "Unexpected DFS NameList ReferralEntryFlags.");
                            TestAssertions.Equal(entry.SpecialName, parsedEntry.SpecialName, "Unexpected DFS NameList SpecialName.");
                            TestAssertions.Equal(2, parsedEntry.ExpandedNames.Length, "Unexpected DFS NameList expanded-name count.");
                            TestAssertions.Equal(entry.ExpandedNames[0], parsedEntry.ExpandedNames[0], "Unexpected first DFS NameList expanded name.");
                            TestAssertions.Equal(entry.ExpandedNames[1], parsedEntry.ExpandedNames[1], "Unexpected second DFS NameList expanded name.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Dfs",
                        caseId: "DfsReferralRequestExRoundTripsRequestFileNameAndOptionalSiteNameAndRejectsTruncatedBuffers",
                        displayName: "Bounded DFS_GET_REFERRALS_EX request round-trips RequestFileName and optional SiteName and rejects truncated buffers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            DfsReferralRequestEx withSite = new DfsReferralRequestEx
                            {
                                MaxReferralLevel = 4,
                                IncludeSiteName = true,
                                PathConsumed = 0,
                                RequestFileName = "\\\\dfs.contoso.test\\namespace\\path",
                                SiteName = "Default-First-Site-Name"
                            };
                            byte[] withSiteBytes = withSite.ToByteArray();
                            DfsReferralRequestEx parsedWithSite = DfsReferralRequestEx.ReadFrom(withSiteBytes);
                            TestAssertions.Equal(withSite.MaxReferralLevel, parsedWithSite.MaxReferralLevel, "Unexpected DFS_EX MaxReferralLevel.");
                            TestAssertions.True(parsedWithSite.IncludeSiteName, "DFS_EX should preserve IncludeSiteName flag.");
                            TestAssertions.Equal(withSite.RequestFileName, parsedWithSite.RequestFileName, "Unexpected DFS_EX RequestFileName.");
                            TestAssertions.Equal(withSite.SiteName, parsedWithSite.SiteName, "Unexpected DFS_EX SiteName.");

                            DfsReferralRequestEx withoutSite = new DfsReferralRequestEx
                            {
                                MaxReferralLevel = 3,
                                IncludeSiteName = false,
                                PathConsumed = 8,
                                RequestFileName = "\\\\dfs.contoso.test\\share"
                            };
                            byte[] withoutSiteBytes = withoutSite.ToByteArray();
                            DfsReferralRequestEx parsedWithoutSite = DfsReferralRequestEx.ReadFrom(withoutSiteBytes);
                            TestAssertions.Equal(false, parsedWithoutSite.IncludeSiteName, "DFS_EX should preserve IncludeSiteName=false.");
                            TestAssertions.Equal(withoutSite.PathConsumed, parsedWithoutSite.PathConsumed, "Unexpected DFS_EX PathConsumed.");
                            TestAssertions.Equal(string.Empty, parsedWithoutSite.SiteName, "DFS_EX SiteName should be empty when not included.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralRequestEx.ReadFrom(new byte[] { 0x04, 0x00, 0x01, 0x00 }),
                                "DFS_EX should reject truncated buffers.");

                            byte[] malformedNameListResponse = BuildDfsReferralResponseV3NameListBaseline();
                            malformedNameListResponse[24] = 0x00;
                            malformedNameListResponse[25] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralResponse.ReadFrom(malformedNameListResponse),
                                "DFS V3 NameList responses should reject a missing expanded-name offset when expanded names are declared.");
                            return Task.CompletedTask;
                        })
                });
        }

    }
}

