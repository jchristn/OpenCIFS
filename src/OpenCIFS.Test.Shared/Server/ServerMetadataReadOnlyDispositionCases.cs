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
    internal static class ServerMetadataReadOnlyDispositionCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRejectsDispositionDeletePendingOnReadOnlyFilesAndDirectories",
                        displayName: "Server rejects FILE_DISPOSITION_INFORMATION delete-pending on read-only files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("readonly-file.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, readOnlyFileOpen.Status, "Expected opening the read-only file for disposition coverage to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyFileDisposition = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = readOnlyFileOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyFileOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyFileDisposition.Status, "Expected read-only files to reject FILE_DISPOSITION_INFORMATION delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyFileStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = readOnlyFileOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyFileOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyFileStandardResult.Status, "Expected FILE_STANDARD_INFORMATION query on the read-only file to succeed after the failed delete-pending request.");
                                FileStandardInformation readOnlyFileStandard = FileStandardInformation.ReadFrom(readOnlyFileStandardResult.Response.OutputBuffer);
                                TestAssertions.False(readOnlyFileStandard.DeletePending, "Expected failed read-only file disposition requests not to mark the file delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyFileClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = readOnlyFileOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyFileOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyFileClose.Status, "Expected the read-only file open to close cleanly after the failed delete-pending request.");
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the read-only file to remain after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "readonly-directory",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory));
                                TestAssertions.Equal(NtStatus.Success, readOnlyDirectoryOpen.Status, "Expected opening the read-only directory for disposition coverage to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyDirectoryDisposition = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.DispositionInformation,
                                        PersistentFileId = readOnlyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyDirectoryOpen.Response.VolatileFileId,
                                        Buffer = new FileDispositionInformation
                                        {
                                            DeletePending = true
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.CannotDelete, readOnlyDirectoryDisposition.Status, "Expected read-only directories to reject FILE_DISPOSITION_INFORMATION delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyDirectoryStandardResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = readOnlyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyDirectoryOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyDirectoryStandardResult.Status, "Expected FILE_STANDARD_INFORMATION query on the read-only directory to succeed after the failed delete-pending request.");
                                FileStandardInformation readOnlyDirectoryStandard = FileStandardInformation.ReadFrom(readOnlyDirectoryStandardResult.Response.OutputBuffer);
                                TestAssertions.False(readOnlyDirectoryStandard.DeletePending, "Expected failed read-only directory disposition requests not to mark the directory delete-pending.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyDirectoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = readOnlyDirectoryOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyDirectoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyDirectoryClose.Status, "Expected the read-only directory open to close cleanly after the failed delete-pending request.");
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the read-only directory to remain after the failed disposition request.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
            };
        }
    }
}
