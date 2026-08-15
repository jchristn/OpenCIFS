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
    internal static class ServerMetadataUnsupportedAccessCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerRejectsUnsupportedMetadataAccessPatterns",
                        displayName: "Server rejects unsupported metadata and directory-enumeration access patterns",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "restricted.txt"), "seed");
                            File.WriteAllText(Path.Combine(sharePath, "folder", "alpha.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;

                                OpenCifsServerOperationResult<Smb2CreateResponse> writeOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0x40000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, writeOnlyOpen.Status, "Expected write-only metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> deniedQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = writeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = writeOnlyOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedQueryResult.Status, "Expected FILE_BASIC_INFORMATION to require read-attributes access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> writeOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = writeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = writeOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, writeOnlyClose.Status, "Expected the write-only test open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> fullOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, fullOpen.Status, "Expected full-access metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> bufferTooSmallResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 8,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.BufferTooSmall, bufferTooSmallResult.Status, "Expected undersized metadata output buffers to be rejected.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> unsupportedFileSystemInfoResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.ObjectIdInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.NotSupported, unsupportedFileSystemInfoResult.Status, "Expected unsupported filesystem query-info classes to remain rejected.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidRenameResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.RenameInformation,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        Buffer = new FileRenameInformationType2
                                        {
                                            ReplaceIfExists = false,
                                            RootDirectory = 1,
                                            FileName = "invalid.txt"
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidRenameResult.Status, "Expected rooted FILE_RENAME_INFORMATION_TYPE_2 requests to be rejected.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> invalidTimestampResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue - 2
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.InvalidParameter, invalidTimestampResult.Status, "Expected FILE_BASIC_INFORMATION timestamp values less than -2 to be rejected.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> fullClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, fullClose.Status, "Expected the full-access test open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0x80000000U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, readOnlyOpen.Status, "Expected read-only metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> deniedSetResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = readOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyOpen.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            LastWriteTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 8, DateTimeKind.Utc).ToFileTimeUtc()),
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedSetResult.Status, "Expected FILE_BASIC_INFORMATION updates to require write-attributes access.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = readOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = readOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, readOnlyClose.Status, "Expected the read-only test open to close cleanly.");

                                string restrictedPath = Path.Combine(sharePath, "restricted.txt");
                                File.SetAttributes(restrictedPath, System.IO.FileAttributes.ReadOnly | System.IO.FileAttributes.Hidden);

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest("restricted.txt", Smb2CreateDisposition.Open, desiredAccess: 0x00000180U, shareAccess: 0x00000007U));
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyOpen.Status, "Expected attribute-only metadata opens on read-only files to succeed.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> clearReadOnlyResult = host.HandleSetInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2SetInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId,
                                        Buffer = new FileBasicInformation
                                        {
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }.ToByteArray()
                                    });
                                TestAssertions.Equal(NtStatus.Success, clearReadOnlyResult.Status, "Expected attribute-only FILE_BASIC_INFORMATION updates to clear the read-only attribute.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> attributeOnlyQueryResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.BasicInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyQueryResult.Status, "Expected attribute-only metadata queries to succeed after clearing the read-only attribute.");
                                FileBasicInformation attributeOnlyBasicInformation = FileBasicInformation.ReadFrom(attributeOnlyQueryResult.Response.OutputBuffer);
                                TestAssertions.False((attributeOnlyBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.ReadOnly) != 0, "Expected FILE_BASIC_INFORMATION updates to clear the read-only attribute.");
                                TestAssertions.True((attributeOnlyBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected FILE_BASIC_INFORMATION updates to preserve the hidden attribute.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> deniedAttributeOnlyReadResult = host.HandleRead(
                                    sessionId,
                                    treeId,
                                    new Smb2ReadRequest
                                    {
                                        Length = 1,
                                        Offset = 0,
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId,
                                        MinimumCount = 0,
                                        Channel = 0,
                                        RemainingBytes = 0,
                                        ReadChannelInfo = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedAttributeOnlyReadResult.Status, "Expected attribute-only metadata opens not to grant file-read data access.");
                                TestAssertions.False((File.GetAttributes(restrictedPath) & System.IO.FileAttributes.ReadOnly) != 0, "Expected the backing file to have its read-only attribute cleared.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> attributeOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = attributeOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = attributeOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, attributeOnlyClose.Status, "Expected the attribute-only metadata open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> fileEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = fullOpen.Response.PersistentFileId,
                                        VolatileFileId = fullOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.FileClosed, fileEnumerationResult.Status, "Expected query-directory to reject file handles that have already been closed.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryWriteOnlyOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x40000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryWriteOnlyOpen.Status, "Expected the write-only directory test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> deniedEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryWriteOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryWriteOnlyOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedEnumerationResult.Status, "Expected query-directory to require read/list access on a directory handle.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryWriteOnlyClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryWriteOnlyOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryWriteOnlyOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryWriteOnlyClose.Status, "Expected the write-only directory open to close cleanly.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryReadOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryReadOpen.Status, "Expected the read-only directory test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> idBothEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.IdBothDirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.Success, idBothEnumerationResult.Status, "Expected FILE_ID_BOTH_DIR_INFORMATION query-directory requests to succeed.");
                                FileIdBothDirectoryInformationEntry[] idBothEntries = FileIdBothDirectoryInformationEntry.DecodeEntries(idBothEnumerationResult.Response.OutputBuffer);
                                TestAssertions.True(idBothEntries.Length >= 1, "Expected FILE_ID_BOTH_DIR_INFORMATION enumeration to return at least one entry.");
                                TestAssertions.True(Array.Exists(idBothEntries, entry => string.Equals(entry.FileName, "alpha.txt", StringComparison.OrdinalIgnoreCase)), "Expected FILE_ID_BOTH_DIR_INFORMATION enumeration to include alpha.txt.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> bothEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.BothDirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "alpha.txt"
                                    });
                                TestAssertions.Equal(NtStatus.Success, bothEnumerationResult.Status, "Expected FILE_BOTH_DIR_INFORMATION query-directory requests to succeed.");
                                FileBothDirectoryInformationEntry[] bothEntries = FileBothDirectoryInformationEntry.DecodeEntries(bothEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, bothEntries.Length, "Expected FILE_BOTH_DIR_INFORMATION enumeration to return the requested entry.");
                                TestAssertions.Equal("alpha.txt", bothEntries[0].FileName, "Expected FILE_BOTH_DIR_INFORMATION enumeration to include alpha.txt.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> unsupportedEnumerationClassResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.StreamInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.InvalidInfoClass, unsupportedEnumerationClassResult.Status, "Expected unsupported query-directory info classes to remain rejected.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> smallBufferEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 16,
                                        FileNamePattern = "alpha.txt"
                                    });
                                TestAssertions.Equal(NtStatus.InfoLengthMismatch, smallBufferEnumerationResult.Status, "Expected undersized query-directory output buffers to be rejected.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> missingEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*.bak"
                                    });
                                TestAssertions.Equal(NtStatus.NoSuchFile, missingEnumerationResult.Status, "Expected a first-pass query-directory miss to report STATUS_NO_SUCH_FILE.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryReadClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryReadOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryReadOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryReadClose.Status, "Expected the read-only directory open to close cleanly.");
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
                    ,
            };
        }
    }
}
