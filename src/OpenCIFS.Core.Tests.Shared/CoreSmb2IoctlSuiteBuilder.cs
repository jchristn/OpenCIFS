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
    internal static class CoreSmb2IoctlSuiteBuilder
    {
        internal static TestSuiteDescriptor Smb2IoctlSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Ioctl",
                displayName: "SMB2 IOCTL messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Ioctl",
                        caseId: "IoctlMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 IOCTL messages round-trip and trim compounded zero padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2IoctlRequest request = new Smb2IoctlRequest
                            {
                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                PersistentFileId = 301,
                                VolatileFileId = 302,
                                MaxInputResponse = 0,
                                MaxOutputResponse = 4096,
                                Flags = Smb2IoctlFlags.IsFsctl,
                                InputBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 }
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb2IoctlRequest parsedRequest = Smb2IoctlRequest.ReadFrom(requestBytes);
                            Smb2IoctlRequestValidator.Validate(parsedRequest);
                            TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, parsedRequest.CtlCode, "Unexpected IOCTL control code.");
                            TestAssertions.Equal(301UL, parsedRequest.PersistentFileId, "Unexpected IOCTL persistent file identifier.");
                            TestAssertions.Equal(302UL, parsedRequest.VolatileFileId, "Unexpected IOCTL volatile file identifier.");
                            TestAssertions.SequenceEqual(request.InputBuffer, parsedRequest.InputBuffer, "Unexpected IOCTL input buffer.");

                            byte[] paddedRequest = Combine(requestBytes, new byte[8]);
                            byte[] trimmedRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Ioctl, paddedRequest);
                            TestAssertions.SequenceEqual(requestBytes, trimmedRequest, "Unexpected compounded IOCTL request trimming result.");

                            Smb2IoctlResponse response = new Smb2IoctlResponse
                            {
                                CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                PersistentFileId = UInt64.MaxValue,
                                VolatileFileId = UInt64.MaxValue,
                                InputBuffer = new byte[] { 0xAA, 0xBB, 0xCC },
                                OutputBuffer = new byte[] { 0x41, 0x42, 0x43, 0x44 },
                                Flags = 0
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb2IoctlResponse parsedResponse = Smb2IoctlResponse.ReadFrom(responseBytes);
                            Smb2IoctlResponseValidator.Validate(parsedResponse);
                            TestAssertions.Equal((uint)FsctlCode.QueryNetworkInterfaceInfo, parsedResponse.CtlCode, "Unexpected IOCTL response control code.");
                            TestAssertions.SequenceEqual(response.InputBuffer, parsedResponse.InputBuffer, "Unexpected IOCTL response input buffer.");
                            TestAssertions.SequenceEqual(response.OutputBuffer, parsedResponse.OutputBuffer, "Unexpected IOCTL response output buffer.");
                            TestAssertions.SequenceEqual(responseBytes, parsedResponse.ToByteArray(), "The SMB2 IOCTL response encoding changed.");

                            byte[] paddedResponse = Combine(responseBytes, new byte[8]);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Ioctl, paddedResponse);
                            TestAssertions.SequenceEqual(responseBytes, trimmedResponse, "Unexpected compounded IOCTL response trimming result.");

                            SrvSnapshotArray snapshotArray = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 2,
                                Snapshots = new string[]
                                {
                                    "@GMT-2025.01.02-03.04.05",
                                    "@GMT-2025.06.07-08.09.10"
                                }
                            };
                            byte[] snapshotArrayBytes = snapshotArray.ToByteArray();
                            SrvSnapshotArray parsedSnapshotArray = SrvSnapshotArray.ReadFrom(snapshotArrayBytes);
                            TestAssertions.Equal(2U, parsedSnapshotArray.NumberOfSnapshots, "Unexpected snapshot-array total count.");
                            TestAssertions.Equal(2, parsedSnapshotArray.Snapshots.Length, "Unexpected snapshot-array returned count.");
                            TestAssertions.Equal("@GMT-2025.01.02-03.04.05", parsedSnapshotArray.Snapshots[0], "Unexpected first snapshot token.");
                            TestAssertions.Equal("@GMT-2025.06.07-08.09.10", parsedSnapshotArray.Snapshots[1], "Unexpected second snapshot token.");

                            SrvSnapshotArray emptySnapshotArray = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 0,
                                Snapshots = Array.Empty<string>()
                            };
                            byte[] emptySnapshotArrayBytes = emptySnapshotArray.ToByteArray();
                            SrvSnapshotArray parsedEmptySnapshotArray = SrvSnapshotArray.ReadFrom(emptySnapshotArrayBytes);
                            TestAssertions.Equal(0U, parsedEmptySnapshotArray.NumberOfSnapshots, "Unexpected empty snapshot-array total count.");
                            TestAssertions.Equal(0, parsedEmptySnapshotArray.Snapshots.Length, "Expected empty snapshot arrays to decode without tokens.");

                            ValidateNegotiateInfoRequest validateRequest = new ValidateNegotiateInfoRequest
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ClientGuid = Guid.Parse("9B3FD6EF-0A95-4C70-9010-6C37083384F0"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };
                            byte[] validateRequestBytes = validateRequest.ToByteArray();
                            ValidateNegotiateInfoRequest parsedValidateRequest = ValidateNegotiateInfoRequest.ReadFrom(validateRequestBytes);
                            TestAssertions.Equal(validateRequest.Capabilities, parsedValidateRequest.Capabilities, "Unexpected VALIDATE_NEGOTIATE_INFO request capabilities.");
                            TestAssertions.Equal(validateRequest.ClientGuid, parsedValidateRequest.ClientGuid, "Unexpected VALIDATE_NEGOTIATE_INFO request GUID.");
                            TestAssertions.Equal(validateRequest.SecurityMode, parsedValidateRequest.SecurityMode, "Unexpected VALIDATE_NEGOTIATE_INFO request security mode.");
                            TestAssertions.Equal(2, parsedValidateRequest.Dialects.Length, "Unexpected VALIDATE_NEGOTIATE_INFO request dialect count.");
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedValidateRequest.Dialects[0], "Unexpected first VALIDATE_NEGOTIATE_INFO request dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, parsedValidateRequest.Dialects[1], "Unexpected second VALIDATE_NEGOTIATE_INFO request dialect.");

                            ValidateNegotiateInfoResponse validateResponse = new ValidateNegotiateInfoResponse
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ServerGuid = Guid.Parse("18E0CDBA-F663-4BF3-B328-A365A8449750"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb2002
                            };
                            byte[] validateResponseBytes = validateResponse.ToByteArray();
                            ValidateNegotiateInfoResponse parsedValidateResponse = ValidateNegotiateInfoResponse.ReadFrom(validateResponseBytes);
                            TestAssertions.Equal(validateResponse.Capabilities, parsedValidateResponse.Capabilities, "Unexpected VALIDATE_NEGOTIATE_INFO response capabilities.");
                            TestAssertions.Equal(validateResponse.ServerGuid, parsedValidateResponse.ServerGuid, "Unexpected VALIDATE_NEGOTIATE_INFO response GUID.");
                            TestAssertions.Equal(validateResponse.SecurityMode, parsedValidateResponse.SecurityMode, "Unexpected VALIDATE_NEGOTIATE_INFO response security mode.");
                            TestAssertions.Equal(validateResponse.Dialect, parsedValidateResponse.Dialect, "Unexpected VALIDATE_NEGOTIATE_INFO response dialect.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Ioctl",
                        caseId: "IoctlValidatorsRejectUnsupportedInputs",
                        displayName: "SMB2 IOCTL validators reject malformed identifiers, flags, and payload shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(null!),
                                "A null SMB2 IOCTL request should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(new Smb2IoctlRequest
                                {
                                    CtlCode = 0,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "SMB2 IOCTL requests should require a non-zero control code.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(new Smb2IoctlRequest
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "SMB2 IOCTL requests should reject partial wildcard file identifiers.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(new Smb2IoctlRequest
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = 0,
                                    VolatileFileId = 0,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "SMB2 IOCTL requests should require a concrete or wildcard file identifier pair.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlResponseValidator.Validate(new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = UInt64.MaxValue,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = Array.Empty<byte>(),
                                    Flags = 1
                                }),
                                "SMB2 IOCTL responses should reject non-zero reserved flags.");

                            byte[] malformedRequestBytes = new Smb2IoctlRequest
                            {
                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                MaxOutputResponse = 256,
                                Flags = Smb2IoctlFlags.IsFsctl,
                                InputBuffer = Array.Empty<byte>()
                            }.ToByteArray();
                            malformedRequestBytes[40] = 0x01;
                            malformedRequestBytes[41] = 0x00;
                            malformedRequestBytes[42] = 0x00;
                            malformedRequestBytes[43] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2IoctlRequest.ReadFrom(malformedRequestBytes),
                                "SMB2 IOCTL requests should reject non-zero output counts.");

                            byte[] malformedResponseBytes = new Smb2IoctlResponse
                            {
                                CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                PersistentFileId = UInt64.MaxValue,
                                VolatileFileId = UInt64.MaxValue,
                                InputBuffer = Array.Empty<byte>(),
                                OutputBuffer = new byte[] { 0x01, 0x02 },
                                Flags = 0
                            }.ToByteArray();
                            malformedResponseBytes[32] = 0x71;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2IoctlResponse.ReadFrom(malformedResponseBytes),
                                "SMB2 IOCTL responses should reject unaligned output-buffer offsets.");

                            byte[] paddedResponse = Combine(
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = Array.Empty<byte>(),
                                    Flags = 0
                                }.ToByteArray(),
                                new byte[] { 0x7F });
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Ioctl, paddedResponse),
                                "Compounded IOCTL responses should reject non-zero trailing padding.");

                            byte[] malformedSnapshotArrayBytes = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 1,
                                Snapshots = new string[] { "@GMT-2025.01.02-03.04.05" }
                            }.ToByteArray();
                            malformedSnapshotArrayBytes[8] = 0x01;
                            malformedSnapshotArrayBytes[9] = 0x00;
                            malformedSnapshotArrayBytes[10] = 0x00;
                            malformedSnapshotArrayBytes[11] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvSnapshotArray.ReadFrom(malformedSnapshotArrayBytes),
                                "SRV_SNAPSHOT_ARRAY should reject payloads whose declared array length does not match the available bytes.");

                            byte[] invalidSnapshotTokenBytes = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 1,
                                Snapshots = new string[] { "@GMT-2025.01.02-03.04.05" }
                            }.ToByteArray();
                            invalidSnapshotTokenBytes[12] = 0x4E;
                            invalidSnapshotTokenBytes[13] = 0x00;
                            invalidSnapshotTokenBytes[14] = 0x4F;
                            invalidSnapshotTokenBytes[15] = 0x00;
                            invalidSnapshotTokenBytes[16] = 0x50;
                            invalidSnapshotTokenBytes[17] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvSnapshotArray.ReadFrom(invalidSnapshotTokenBytes),
                                "SRV_SNAPSHOT_ARRAY should reject tokens that do not use the expected @GMT format.");

                            byte[] invalidValidateRequestBytes = new ValidateNegotiateInfoRequest
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ClientGuid = Guid.Parse("D1B8A5FB-9F30-4BF4-84E9-33616D5F8265"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialects = new[] { SmbDialect.Smb2002 }
                            }.ToByteArray();
                            invalidValidateRequestBytes[22] = 0x00;
                            invalidValidateRequestBytes[23] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => ValidateNegotiateInfoRequest.ReadFrom(invalidValidateRequestBytes),
                                "VALIDATE_NEGOTIATE_INFO requests should reject a zero dialect count.");

                            byte[] invalidValidateResponseBytes = new ValidateNegotiateInfoResponse
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ServerGuid = Guid.Parse("6393D0FF-5149-40D7-9C67-7268E6AF47F7"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb2002
                            }.ToByteArray();
                            invalidValidateResponseBytes[22] = 0x99;
                            invalidValidateResponseBytes[23] = 0x99;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => ValidateNegotiateInfoResponse.ReadFrom(invalidValidateResponseBytes),
                                "VALIDATE_NEGOTIATE_INFO responses should reject unknown dialect values.");
                            return Task.CompletedTask;
                        })
                });
        }

    }
}

