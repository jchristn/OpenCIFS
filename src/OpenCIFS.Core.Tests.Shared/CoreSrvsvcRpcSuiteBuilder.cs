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
    internal static class CoreSrvsvcRpcSuiteBuilder
    {
        internal static TestSuiteDescriptor SrvsvcRpcSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.SrvsvcRpc",
                displayName: "SRVSVC RPC messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareEnumMessagesEncodeAndParseBoundedLevel1Shapes",
                        displayName: "SRVSVC share enumeration request and response encode bounded level 1 shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SrvsvcNetrShareEnumRequest request = new SrvsvcNetrShareEnumRequest
                            {
                                ServerName = string.Empty,
                                Level = 1,
                                PreferredMaximumLength = 0xFFFFFFFFU,
                                ResumeHandle = 9
                            };
                            byte[] requestBytes = request.ToByteArray();
                            LittleEndianReader requestReader = new LittleEndianReader(requestBytes);

                            TestAssertions.Equal((uint)0x00010000, requestReader.ReadUInt32(), "Expected the SRVSVC server-name pointer to remain non-null in the bounded request shape.");
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC server-name maximum count.");
                            TestAssertions.Equal((uint)0, requestReader.ReadUInt32(), "Unexpected SRVSVC server-name offset.");
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC server-name actual count.");
                            TestAssertions.Equal((ushort)0x0000, requestReader.ReadUInt16(), "Expected the bounded SRVSVC server-name string to be empty and null terminated.");
                            requestReader.Skip(2);
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC level value.");
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC union tag value.");
                            TestAssertions.Equal((uint)0x00020000, requestReader.ReadUInt32(), "Unexpected SRVSVC level-1 container pointer value.");
                            TestAssertions.Equal((uint)0, requestReader.ReadUInt32(), "Unexpected SRVSVC level-1 entries-read seed value.");
                            TestAssertions.Equal((uint)0, requestReader.ReadUInt32(), "Unexpected SRVSVC level-1 buffer pointer seed value.");
                            TestAssertions.Equal((uint)0xFFFFFFFFU, requestReader.ReadUInt32(), "Unexpected SRVSVC preferred maximum length.");
                            TestAssertions.Equal((uint)0x00030000, requestReader.ReadUInt32(), "Unexpected SRVSVC resume-handle pointer value.");
                            TestAssertions.Equal((uint)9, requestReader.ReadUInt32(), "Unexpected SRVSVC resume-handle seed value.");

                            LittleEndianWriter responseWriter = new LittleEndianWriter();
                            responseWriter.WriteUInt32(1);
                            responseWriter.WriteUInt32(1);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00020000);
                            responseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00030000);
                            responseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00040000);
                            responseWriter.WriteUInt32(0);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00050000);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00060000);
                            responseWriter.WriteUInt32(0x80000003U);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00070000);
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "share");
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "sample share");
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "IPC$");
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "remote ipc");
                            responseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00080000);
                            responseWriter.WriteUInt32(4);
                            responseWriter.WriteUInt32(0);

                            SrvsvcNetrShareEnumResponse response = SrvsvcNetrShareEnumResponse.ReadFrom(responseWriter.ToArray());
                            TestAssertions.Equal((uint)1, response.Level, "Unexpected SRVSVC response level.");
                            TestAssertions.Equal((uint)2, response.TotalEntries, "Unexpected SRVSVC total entry count.");
                            TestAssertions.Equal((uint)4, response.ResumeHandle!.Value, "Unexpected SRVSVC resume handle value.");
                            TestAssertions.Equal((uint)0, response.ReturnCode, "Unexpected SRVSVC return code.");
                            TestAssertions.Equal(2, response.Shares.Length, "Unexpected SRVSVC share count.");
                            TestAssertions.Equal("share", response.Shares[0].Name, "Unexpected first SRVSVC share name.");
                            TestAssertions.Equal("sample share", response.Shares[0].Remark, "Unexpected first SRVSVC share remark.");
                            TestAssertions.Equal((uint)0, response.Shares[0].Type, "Unexpected first SRVSVC share type.");
                            TestAssertions.Equal("IPC$", response.Shares[1].Name, "Unexpected second SRVSVC share name.");
                            TestAssertions.Equal("remote ipc", response.Shares[1].Remark, "Unexpected second SRVSVC share remark.");
                            TestAssertions.Equal((uint)0x80000003U, response.Shares[1].Type, "Unexpected second SRVSVC share type.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareEnumReadersRejectMalformedInputs",
                        displayName: "SRVSVC share enumeration readers reject malformed request and response inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => new SrvsvcNetrShareEnumRequest
                                {
                                    Level = 2
                                }.ToByteArray(),
                                "The bounded SRVSVC request slice should reject unsupported levels.");

                            LittleEndianWriter invalidResponseWriter = new LittleEndianWriter();
                            invalidResponseWriter.WriteUInt32(1);
                            invalidResponseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(invalidResponseWriter, 0);
                            invalidResponseWriter.WriteUInt32(0);
                            DceRpcEncoding.WriteUniquePointer(invalidResponseWriter, 0);
                            invalidResponseWriter.WriteUInt32(0);

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareEnumResponse.ReadFrom(invalidResponseWriter.ToArray()),
                                "The bounded SRVSVC response reader should reject mismatched union tags.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareEnumResponse.ReadFrom(new byte[7]),
                                "The bounded SRVSVC response reader should reject truncated payloads.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareGetInfoMessagesEncodeAndParseBoundedLevel2Shapes",
                        displayName: "SRVSVC share-info request and response encode bounded level 2 shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SrvsvcNetrShareGetInfoRequest request = new SrvsvcNetrShareGetInfoRequest
                            {
                                ServerName = string.Empty,
                                ShareName = "public",
                                Level = 2
                            };
                            byte[] requestBytes = request.ToByteArray();
                            SrvsvcNetrShareGetInfoRequest parsedRequest = SrvsvcNetrShareGetInfoRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(string.Empty, parsedRequest.ServerName, "Unexpected SRVSVC get-info server name.");
                            TestAssertions.Equal("public", parsedRequest.ShareName, "Unexpected SRVSVC get-info share name.");
                            TestAssertions.Equal((uint)2, parsedRequest.Level, "Unexpected SRVSVC get-info level.");

                            SrvsvcNetrShareGetInfoResponse successResponse = SrvsvcNetrShareGetInfoResponse.Create(
                                new SrvsvcShareInfo2
                                {
                                    Name = "public",
                                    Type = 0,
                                    Remark = "sample share",
                                    Permissions = 0,
                                    MaximumUses = UInt32.MaxValue,
                                    CurrentUses = 3,
                                    Path = @"C:\shares\public",
                                    Password = string.Empty
                                },
                                SrvsvcNetrShareGetInfoResponse.ErrorSuccess);
                            SrvsvcNetrShareGetInfoResponse parsedSuccessResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(successResponse.ToByteArray());
                            TestAssertions.Equal((uint)0, parsedSuccessResponse.ReturnCode, "Unexpected SRVSVC get-info success return code.");
                            TestAssertions.True(parsedSuccessResponse.Share != null, "Expected SRVSVC get-info success responses to carry share details.");
                            TestAssertions.Equal("public", parsedSuccessResponse.Share!.Name, "Unexpected SRVSVC get-info share name.");
                            TestAssertions.Equal("sample share", parsedSuccessResponse.Share.Remark, "Unexpected SRVSVC get-info share remark.");
                            TestAssertions.Equal((uint)3, parsedSuccessResponse.Share.CurrentUses, "Unexpected SRVSVC get-info current use count.");
                            TestAssertions.Equal(@"C:\shares\public", parsedSuccessResponse.Share.Path, "Unexpected SRVSVC get-info share path.");

                            SrvsvcNetrShareGetInfoResponse missingResponse = SrvsvcNetrShareGetInfoResponse.Create(
                                share: null,
                                returnCode: SrvsvcNetrShareGetInfoResponse.NerrNetNameNotFound);
                            SrvsvcNetrShareGetInfoResponse parsedMissingResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(missingResponse.ToByteArray());
                            TestAssertions.Equal(SrvsvcNetrShareGetInfoResponse.NerrNetNameNotFound, parsedMissingResponse.ReturnCode, "Unexpected SRVSVC get-info missing-share return code.");
                            TestAssertions.True(parsedMissingResponse.Share == null, "Expected SRVSVC get-info missing-share responses not to carry share details.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareGetInfoReadersRejectMalformedInputs",
                        displayName: "SRVSVC share-info readers reject malformed request and response inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ArgumentNullException>(
                                () => new SrvsvcNetrShareGetInfoRequest
                                {
                                    ShareName = string.Empty
                                }.ToByteArray(),
                                "The bounded SRVSVC get-info request slice should reject missing share names.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => new SrvsvcNetrShareGetInfoRequest
                                {
                                    ShareName = "public",
                                    Level = 1
                                }.ToByteArray(),
                                "The bounded SRVSVC get-info request slice should reject unsupported levels.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareGetInfoRequest.ReadFrom(new byte[7]),
                                "The bounded SRVSVC get-info request reader should reject truncated payloads.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareGetInfoResponse.ReadFrom(new byte[7]),
                                "The bounded SRVSVC get-info response reader should reject truncated payloads.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareGetInfoResponse.ReadFrom(new byte[]
                                {
                                    0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00
                                }),
                                "The bounded SRVSVC get-info response reader should reject success without share details.");

                            return Task.CompletedTask;
                        })
                });
        }

    }
}

