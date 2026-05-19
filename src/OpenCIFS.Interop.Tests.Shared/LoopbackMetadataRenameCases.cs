namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class LoopbackMetadataRenameCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> BuildCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerRenameDirectoriesThroughBoundedSetInfo",
                        displayName: "Client and server loopback rename directories through bounded FILE_RENAME_INFORMATION",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "archive"));
                            Directory.CreateDirectory(Path.Combine(sharePath, "source"));
                            File.WriteAllText(Path.Combine(sharePath, "source", "child.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest childOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "source/child.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> childOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, childOpenRequest);
                                OpenState childOpen = client.ApplyCreateResult(treeId, "source/child.txt", childOpenResult.Status, childOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> childAllocationResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(childOpen.PersistentFileId, childOpen.VolatileFileId, 96));
                                client.ApplySetInfoResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childAllocationResult.Status, childAllocationResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> childCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(childOpen.PersistentFileId, childOpen.VolatileFileId));
                                client.ApplyCloseResult(childOpen.PersistentFileId, childOpen.VolatileFileId, childCloseResult.Status, childCloseResult.Response);

                                Smb2CreateRequest directoryOpenRequest = client.CreateCreateRequest(
                                    treeId,
                                    "source",
                                    desiredAccess: 0x80010000U,
                                    fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open,
                                    createOptions: Smb2CreateOptions.DirectoryFile);
                                OpenCifsServerOperationResult<Smb2CreateResponse> directoryOpenResult = server.HandleCreate(client.SessionId!.Value, treeId, directoryOpenRequest);
                                OpenState directoryOpen = client.ApplyCreateResult(treeId, "source", directoryOpenResult.Status, directoryOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> directoryRenameResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetRenameInfoRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, "archive/renamed-folder"));
                                client.ApplySetRenameInfoResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryRenameResult.Status, directoryRenameResult.Response, "archive/renamed-folder");
                                TestAssertions.Equal("archive\\renamed-folder", directoryOpen.Path, "Expected the loopback directory rename to update the tracked open path.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> renamedDirectoryNameResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, FileInformationClass.NameInformation));
                                FileNameInformation renamedDirectoryName = FileNameInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, renamedDirectoryNameResult.Status, renamedDirectoryNameResult.Response));
                                TestAssertions.Equal("archive\\renamed-folder", renamedDirectoryName.FileName, "Unexpected loopback FILE_NAME_INFORMATION path after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> movedChildOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "archive/renamed-folder/child.txt", createDisposition: Smb2CreateDisposition.Open));
                                OpenState movedChildOpen = client.ApplyCreateResult(treeId, "archive/renamed-folder/child.txt", movedChildOpenResult.Status, movedChildOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> movedChildStandardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation movedChildStandardInformation = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId, movedChildStandardResult.Status, movedChildStandardResult.Response));
                                TestAssertions.Equal(96UL, movedChildStandardInformation.AllocationSize, "Expected declared allocation state to move with the renamed directory subtree.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> movedChildCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId));
                                client.ApplyCloseResult(movedChildOpen.PersistentFileId, movedChildOpen.VolatileFileId, movedChildCloseResult.Status, movedChildCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> oldPathOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(treeId, "source/child.txt", createDisposition: Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.ObjectPathNotFound, oldPathOpenResult.Status, "Expected the old loopback child path to disappear after the directory rename.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> directoryCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId));
                                client.ApplyCloseResult(directoryOpen.PersistentFileId, directoryOpen.VolatileFileId, directoryCloseResult.Status, directoryCloseResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear directory and moved-child opens after the bounded loopback rename slice closes them.");
                                TestAssertions.True(Directory.Exists(Path.Combine(sharePath, "archive", "renamed-folder")), "Expected the renamed loopback directory to remain at its destination path.");
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
            };
        }
    }
}
