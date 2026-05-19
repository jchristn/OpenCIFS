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
    internal static class Smb1NegotiationSessionAndTreeCases
    {
        internal static List<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NegotiateResponseRoundTripsExtendedSecurityShape",
                        displayName: "Bounded SMB1 NEGOTIATE response round-trips the NT LM 0.12 extended-security shape",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] securityBlob = new byte[]
                            {
                                0x60, 0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
                                0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C
                            };

                            Smb1NegotiateResponse response = new Smb1NegotiateResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Negotiate,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    ProcessIdHigh = 0,
                                    Signature = new byte[8],
                                    TreeId = 0,
                                    ProcessIdLow = 0xFEED,
                                    UserId = 0,
                                    MultiplexId = 0x1234
                                },
                                DialectIndex = 5,
                                SecurityMode = Smb1SecurityMode.UserSecurity | Smb1SecurityMode.EncryptPasswords | Smb1SecurityMode.SigningEnabled | Smb1SecurityMode.SigningRequired,
                                MaxMpxCount = 50,
                                MaxNumberVcs = 1,
                                MaxBufferSize = 65535,
                                MaxRawSize = 65536,
                                SessionKey = 0xDEADBEEFU,
                                Capabilities = Smb1Capabilities.Unicode | Smb1Capabilities.LargeFiles | Smb1Capabilities.NtSmbs | Smb1Capabilities.RpcRemoteApis | Smb1Capabilities.Status32 | Smb1Capabilities.NtFind | Smb1Capabilities.LargeReadX | Smb1Capabilities.LargeWriteX | Smb1Capabilities.ExtendedSecurity,
                                SystemTime = 0x01D811223344AABBUL,
                                ServerTimeZoneMinutes = -480,
                                ServerGuid = Guid.Parse("0F11D8A6-3344-4F2C-8FB0-1A6E6F7B9C50"),
                                SecurityBlob = securityBlob
                            };

                            byte[] wireBytes = response.ToByteArray();
                            Smb1NegotiateResponse parsed = Smb1NegotiateResponse.ReadFrom(wireBytes);

                            TestAssertions.Equal(response.DialectIndex, parsed.DialectIndex, "Unexpected SMB1 dialect index after round-trip.");
                            TestAssertions.Equal(response.SecurityMode, parsed.SecurityMode, "Unexpected SMB1 security mode after round-trip.");
                            TestAssertions.Equal(response.MaxMpxCount, parsed.MaxMpxCount, "Unexpected SMB1 MaxMpxCount after round-trip.");
                            TestAssertions.Equal(response.MaxNumberVcs, parsed.MaxNumberVcs, "Unexpected SMB1 MaxNumberVcs after round-trip.");
                            TestAssertions.Equal(response.MaxBufferSize, parsed.MaxBufferSize, "Unexpected SMB1 MaxBufferSize after round-trip.");
                            TestAssertions.Equal(response.MaxRawSize, parsed.MaxRawSize, "Unexpected SMB1 MaxRawSize after round-trip.");
                            TestAssertions.Equal(response.SessionKey, parsed.SessionKey, "Unexpected SMB1 SessionKey after round-trip.");
                            TestAssertions.Equal(response.Capabilities, parsed.Capabilities, "Unexpected SMB1 capability flags after round-trip.");
                            TestAssertions.Equal(response.SystemTime, parsed.SystemTime, "Unexpected SMB1 SystemTime after round-trip.");
                            TestAssertions.Equal(response.ServerTimeZoneMinutes, parsed.ServerTimeZoneMinutes, "Unexpected SMB1 server time-zone minutes after round-trip.");
                            TestAssertions.Equal(response.ServerGuid, parsed.ServerGuid, "Unexpected SMB1 server GUID after round-trip.");
                            TestAssertions.SequenceEqual(securityBlob, parsed.SecurityBlob, "Unexpected SMB1 SPNEGO security blob after round-trip.");

                            TestAssertions.Equal(Smb1DialectStrings.NtLm012, "NT LM 0.12", "Unexpected NT LM 0.12 dialect string constant.");
                            TestAssertions.Equal(Smb1DialectStrings.LanMan10, "LANMAN1.0", "Unexpected LANMAN1.0 dialect string constant.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1SessionSetupAndXRequestRoundTripsExtendedSecurityShape",
                        displayName: "Bounded SMB1 SESSION_SETUP_ANDX request round-trips the Unicode extended-security shape",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] securityBlob = new byte[]
                            {
                                0x60, 0x82, 0x01, 0x47, 0x06, 0x06, 0x2B, 0x06,
                                0x01, 0x05, 0x05, 0x02, 0xA0, 0x82, 0x01
                            };

                            Smb1SessionSetupAndXRequest request = new Smb1SessionSetupAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.SessionSetupAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    ProcessIdHigh = 0,
                                    Signature = new byte[8],
                                    TreeId = 0,
                                    ProcessIdLow = 0xCAFE,
                                    UserId = 0,
                                    MultiplexId = 0x4242
                                },
                                MaxBufferSize = 4356,
                                MaxMpxCount = 50,
                                VcNumber = 0,
                                SessionKey = 0xDEADBEEFU,
                                Capabilities = Smb1Capabilities.Unicode | Smb1Capabilities.LargeFiles | Smb1Capabilities.NtSmbs | Smb1Capabilities.Status32 | Smb1Capabilities.ExtendedSecurity,
                                SecurityBlob = securityBlob,
                                NativeOS = "Windows 11",
                                NativeLanMan = "OpenCIFS"
                            };

                            byte[] wireBytes = request.ToByteArray();
                            Smb1SessionSetupAndXRequest parsed = Smb1SessionSetupAndXRequest.ReadFrom(wireBytes);
                            TestAssertions.Equal(request.MaxBufferSize, parsed.MaxBufferSize, "Unexpected MaxBufferSize after round-trip.");
                            TestAssertions.Equal(request.MaxMpxCount, parsed.MaxMpxCount, "Unexpected MaxMpxCount after round-trip.");
                            TestAssertions.Equal(request.VcNumber, parsed.VcNumber, "Unexpected VcNumber after round-trip.");
                            TestAssertions.Equal(request.SessionKey, parsed.SessionKey, "Unexpected SessionKey after round-trip.");
                            TestAssertions.Equal(request.Capabilities, parsed.Capabilities, "Unexpected client capabilities after round-trip.");
                            TestAssertions.SequenceEqual(securityBlob, parsed.SecurityBlob, "Unexpected SPNEGO blob after round-trip.");
                            TestAssertions.Equal("Windows 11", parsed.NativeOS, "Unexpected NativeOS after round-trip.");
                            TestAssertions.Equal("OpenCIFS", parsed.NativeLanMan, "Unexpected NativeLanMan after round-trip.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1SessionSetupAndXResponseRoundTripsExtendedSecurityShapeAndPreservesGuestActionBit",
                        displayName: "Bounded SMB1 SESSION_SETUP_ANDX response round-trips the extended-security shape and preserves the guest action bit",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] securityBlob = new byte[]
                            {
                                0xA1, 0x1A, 0x30, 0x18, 0xA0, 0x03, 0x0A, 0x01,
                                0x00, 0xA1, 0x0B
                            };

                            Smb1SessionSetupAndXResponse response = new Smb1SessionSetupAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.SessionSetupAndX,
                                    Status = NtStatus.MoreProcessingRequired,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Action = Smb1SessionSetupAndXResponse.GuestLogonActionBit,
                                SecurityBlob = securityBlob,
                                NativeOS = "OpenCIFS",
                                NativeLanMan = "OpenCIFS",
                                PrimaryDomain = "WORKGROUP"
                            };

                            byte[] wireBytes = response.ToByteArray();
                            Smb1SessionSetupAndXResponse parsed = Smb1SessionSetupAndXResponse.ReadFrom(wireBytes);
                            TestAssertions.Equal(Smb1SessionSetupAndXResponse.GuestLogonActionBit, parsed.Action, "Unexpected SMB1 SESSION_SETUP_ANDX response action flags.");
                            TestAssertions.True(parsed.IsGuestLogon, "Expected the response to indicate a guest logon.");
                            TestAssertions.SequenceEqual(securityBlob, parsed.SecurityBlob, "Unexpected SPNEGO response blob after round-trip.");
                            TestAssertions.Equal("OpenCIFS", parsed.NativeOS, "Unexpected NativeOS after round-trip.");
                            TestAssertions.Equal("OpenCIFS", parsed.NativeLanMan, "Unexpected NativeLanMan after round-trip.");
                            TestAssertions.Equal("WORKGROUP", parsed.PrimaryDomain, "Unexpected PrimaryDomain after round-trip.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TreeConnectAndXRequestAndResponseRoundTripUnicodePathAndAsciiServiceShapes",
                        displayName: "Bounded SMB1 TREE_CONNECT_ANDX request and response round-trip Unicode path and ASCII service shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1TreeConnectAndXRequest request = new Smb1TreeConnectAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TreeConnectAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x0BAD,
                                    MultiplexId = 0x0123
                                },
                                Flags = 0,
                                Password = new byte[] { 0x00 },
                                Path = "\\\\fileserver.contoso.test\\share",
                                Service = "?????"
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1TreeConnectAndXRequest parsedRequest = Smb1TreeConnectAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.SequenceEqual(request.Password, parsedRequest.Password, "Unexpected SMB1 TREE_CONNECT_ANDX password after round-trip.");
                            TestAssertions.Equal(request.Path, parsedRequest.Path, "Unexpected SMB1 TREE_CONNECT_ANDX share path after round-trip.");
                            TestAssertions.Equal(request.Service, parsedRequest.Service, "Unexpected SMB1 TREE_CONNECT_ANDX service after round-trip.");

                            Smb1TreeConnectAndXResponse response = new Smb1TreeConnectAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TreeConnectAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xABCD,
                                    UserId = 0x0BAD,
                                    MultiplexId = 0x0123
                                },
                                OptionalSupport = 0x0001,
                                MaximalShareAccessRights = 0x001F01FFU,
                                GuestMaximalShareAccessRights = 0x00120089U,
                                Service = "A:",
                                NativeFileSystem = "NTFS"
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1TreeConnectAndXResponse parsedResponse = Smb1TreeConnectAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.OptionalSupport, parsedResponse.OptionalSupport, "Unexpected SMB1 TREE_CONNECT_ANDX optional-support flags.");
                            TestAssertions.Equal(response.MaximalShareAccessRights, parsedResponse.MaximalShareAccessRights, "Unexpected SMB1 TREE_CONNECT_ANDX maximal share access rights.");
                            TestAssertions.Equal(response.GuestMaximalShareAccessRights, parsedResponse.GuestMaximalShareAccessRights, "Unexpected SMB1 TREE_CONNECT_ANDX guest share access rights.");
                            TestAssertions.Equal(response.Service, parsedResponse.Service, "Unexpected SMB1 TREE_CONNECT_ANDX echoed service.");
                            TestAssertions.Equal(response.NativeFileSystem, parsedResponse.NativeFileSystem, "Unexpected SMB1 TREE_CONNECT_ANDX NativeFileSystem.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NegotiateResponseRejectsMalformedAndNonExtendedSecurityShapes",
                        displayName: "Bounded SMB1 NEGOTIATE response rejects malformed shapes and non-extended-security responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NegotiateResponse.ReadFrom(new byte[10]),
                                "A truncated SMB1 negotiate response should fail to parse.");

                            Smb1NegotiateResponse missingExtendedSecurity = new Smb1NegotiateResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Negotiate,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus
                                },
                                DialectIndex = 0,
                                SecurityMode = Smb1SecurityMode.UserSecurity | Smb1SecurityMode.EncryptPasswords,
                                Capabilities = Smb1Capabilities.Unicode | Smb1Capabilities.NtSmbs
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => missingExtendedSecurity.ToByteArray(),
                                "The bounded SMB1 negotiate response codec should reject responses without the extended-security capability.");
                            return Task.CompletedTask;
                        })
            };
        }
    }
}

