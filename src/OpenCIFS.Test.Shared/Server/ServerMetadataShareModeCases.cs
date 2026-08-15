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
    internal static class ServerMetadataShareModeCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
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
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
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
            };
        }
    }
}
