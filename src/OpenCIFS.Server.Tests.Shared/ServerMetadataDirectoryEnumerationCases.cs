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
    internal static class ServerMetadataDirectoryEnumerationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Metadata",
                        caseId: "ServerEnumeratesDirectoryEntriesOnTrackedDirectoryOpen",
                        displayName: "Server handles bounded query-directory enumeration on a tracked directory open",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder", "nested"));
                            File.WriteAllText(Path.Combine(sharePath, "folder", "alpha.txt"), "alpha");
                            File.WriteAllText(Path.Combine(sharePath, "folder", "beta.log"), "beta");

                            try
                            {
                                OpenCifsServerHost host = CreateServerHost(sharePath);
                                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                                ulong sessionId = treeContext.SessionId;
                                uint treeId = treeContext.TreeId;
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpen = host.HandleCreate(
                                    sessionId,
                                    treeId,
                                    CreateFileCreateRequest(
                                        "folder",
                                        Smb2CreateDisposition.Open,
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                TestAssertions.Equal(NtStatus.Success, directoryOpen.Status, "Expected the directory metadata test open to succeed.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> standardInfoResult = host.HandleQueryInfo(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.StandardInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                TestAssertions.Equal(NtStatus.Success, standardInfoResult.Status, "Expected FILE_STANDARD_INFORMATION on a directory open to succeed.");
                                FileStandardInformation directoryStandardInformation = FileStandardInformation.ReadFrom(standardInfoResult.Response.OutputBuffer);
                                TestAssertions.True(directoryStandardInformation.Directory, "Expected the directory open to report Directory=true through FILE_STANDARD_INFORMATION.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> firstEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 512,
                                        FileNamePattern = "*"
                                    });
                                TestAssertions.Equal(NtStatus.Success, firstEnumerationResult.Status, "Expected the first directory enumeration result to succeed.");
                                FileDirectoryInformationEntry[] firstEntries = FileDirectoryInformationEntry.DecodeEntries(firstEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, firstEntries.Length, "Expected ReturnSingleEntry to constrain the first directory enumeration result.");
                                TestAssertions.Equal("alpha.txt", firstEntries[0].FileName, "Expected the first directory enumeration result to be sorted alphabetically.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> resumedEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.None,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 4096,
                                        FileNamePattern = string.Empty
                                    });
                                TestAssertions.Equal(NtStatus.Success, resumedEnumerationResult.Status, "Expected the resumed directory enumeration result to succeed.");
                                FileDirectoryInformationEntry[] resumedEntries = FileDirectoryInformationEntry.DecodeEntries(resumedEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(2, resumedEntries.Length, "Expected the resumed directory enumeration to return the remaining entries.");
                                TestAssertions.Equal("beta.log", resumedEntries[0].FileName, "Unexpected second directory enumeration entry.");
                                TestAssertions.Equal("nested", resumedEntries[1].FileName, "Unexpected final directory enumeration entry.");
                                TestAssertions.True(
                                    (resumedEntries[1].FileAttributes & OpenCIFS.Protocol.FileAttributes.Directory) != 0,
                                    "Expected directory enumeration to preserve directory attributes on subdirectories.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> exhaustedEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.DirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.None,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 4096,
                                        FileNamePattern = string.Empty
                                    });
                                TestAssertions.Equal(NtStatus.NoMoreFiles, exhaustedEnumerationResult.Status, "Expected the directory enumeration to report exhaustion after the final entry.");

                                OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> filteredEnumerationResult = host.HandleQueryDirectory(
                                    sessionId,
                                    treeId,
                                    new Smb2QueryDirectoryRequest
                                    {
                                        FileInfoClass = FileInformationClass.FullDirectoryInformation,
                                        Flags = Smb2QueryDirectoryFlags.RestartScans,
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId,
                                        OutputBufferLength = 4096,
                                        FileNamePattern = "*.txt"
                                    });
                                TestAssertions.Equal(NtStatus.Success, filteredEnumerationResult.Status, "Expected the filtered full-directory enumeration to succeed.");
                                FileFullDirectoryInformationEntry[] filteredEntries = FileFullDirectoryInformationEntry.DecodeEntries(filteredEnumerationResult.Response.OutputBuffer);
                                TestAssertions.Equal(1, filteredEntries.Length, "Expected the filtered full-directory enumeration to return a single matching file.");
                                TestAssertions.Equal("alpha.txt", filteredEntries[0].FileName, "Unexpected filtered full-directory entry.");
                                TestAssertions.Equal(0U, filteredEntries[0].EaSize, "Expected the bounded FILE_FULL_DIR_INFORMATION slice to report EaSize=0.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryClose = host.HandleClose(
                                    sessionId,
                                    treeId,
                                    new Smb2CloseRequest
                                    {
                                        PersistentFileId = directoryOpen.Response.PersistentFileId,
                                        VolatileFileId = directoryOpen.Response.VolatileFileId
                                    });
                                TestAssertions.Equal(NtStatus.Success, directoryClose.Status, "Expected the directory metadata test open to close cleanly.");
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
