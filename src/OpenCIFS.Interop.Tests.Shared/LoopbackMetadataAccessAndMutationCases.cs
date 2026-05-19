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
    internal static class LoopbackMetadataAccessAndMutationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> BuildCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerAllowAttributeOnlyReopenWhileStillRejectingDataReadAcrossShareNone",
                        displayName: "Client and server loopback allow attribute-only reopen across share-none while still rejecting data-read reopens",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> exclusiveOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "notes.txt",
                                        desiredAccess: 0x00120196U,
                                        shareAccess: 0x00000000U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState exclusiveOpen = client.ApplyCreateResult(treeId, "notes.txt", exclusiveOpenResult.Status, exclusiveOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "notes.txt",
                                        desiredAccess: 0x00000080U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState attributeOnlyOpen = client.ApplyCreateResult(treeId, "notes.txt", attributeOnlyOpenResult.Status, attributeOnlyOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> internalInformationQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, FileInformationClass.InternalInformation));
                                FileInternalInformation internalInformation = FileInternalInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, internalInformationQueryResult.Status, internalInformationQueryResult.Response));
                                TestAssertions.Equal(attributeOnlyOpen.PersistentFileId, internalInformation.IndexNumber, "Unexpected loopback FILE_INTERNAL_INFORMATION index number for the metadata-only reopen.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> dataReadOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "notes.txt",
                                        desiredAccess: 0x80000000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                TestAssertions.Equal(NtStatus.SharingViolation, dataReadOpenResult.Status, "Expected loopback data-read reopens to remain blocked across a share-none open.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> attributeOnlyCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId));
                                client.ApplyCloseResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, attributeOnlyCloseResult.Status, attributeOnlyCloseResult.Response);

                                OpenCifsServerOperationResult<Smb2CloseResponse> exclusiveCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(exclusiveOpen.PersistentFileId, exclusiveOpen.VolatileFileId));
                                client.ApplyCloseResult(exclusiveOpen.PersistentFileId, exclusiveOpen.VolatileFileId, exclusiveCloseResult.Status, exclusiveCloseResult.Response);
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
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerCompleteMetadataLifecycle",
                        displayName: "Client and server loopback complete bounded query-info and set-info metadata operations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            Directory.CreateDirectory(Path.Combine(sharePath, "folder"));
                            File.WriteAllText(Path.Combine(sharePath, "notes.txt"), "seed");

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                Smb2CreateRequest createRequest = client.CreateCreateRequest(
                                    treeId,
                                    "notes.txt",
                                    desiredAccess: 0xC0010000U,
                                    shareAccess: 0x00000007U,
                                    createDisposition: Smb2CreateDisposition.Open);
                                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = server.HandleCreate(client.SessionId!.Value, treeId, createRequest);
                                OpenState openState = client.ApplyCreateResult(treeId, "notes.txt", createResult.Status, createResult.Response);
                                TestAssertions.Equal(1, client.OpenCount, "Expected the client to track the loopback metadata open.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> allocationResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetAllocationInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 64));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, allocationResult.Status, allocationResult.Response);

                                byte[] payload = Encoding.UTF8.GetBytes("hello world");
                                OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, payload, 0));
                                TestAssertions.Equal((uint)payload.Length, client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeResult.Status, writeResult.Response), "Unexpected loopback metadata write count.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> endOfFileResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetEndOfFileInfoRequest(openState.PersistentFileId, openState.VolatileFileId, 12));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, endOfFileResult.Status, endOfFileResult.Response);

                                ulong creationTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 8, DateTimeKind.Utc).ToFileTimeUtc());
                                ulong lastAccessTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 9, DateTimeKind.Utc).ToFileTimeUtc());
                                ulong lastWriteTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 10, DateTimeKind.Utc).ToFileTimeUtc());
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> basicResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            CreationTime = creationTime,
                                            LastAccessTime = lastAccessTime,
                                            LastWriteTime = lastWriteTime,
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, basicResult.Status, basicResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> standardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, standardResult.Status, standardResult.Response));
                                TestAssertions.Equal(64UL, standardInformation.AllocationSize, "Unexpected loopback FILE_STANDARD_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, standardInformation.EndOfFile, "Unexpected loopback FILE_STANDARD_INFORMATION EOF size.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> basicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation basicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, basicQueryResult.Status, basicQueryResult.Response));
                                TestAssertions.Equal(creationTime, basicInformation.CreationTime, "Unexpected loopback FILE_BASIC_INFORMATION creation time.");
                                TestAssertions.Equal(lastAccessTime, basicInformation.LastAccessTime, "Unexpected loopback FILE_BASIC_INFORMATION last-access time.");
                                TestAssertions.Equal(lastWriteTime, basicInformation.LastWriteTime, "Unexpected loopback FILE_BASIC_INFORMATION last-write time.");
                                TestAssertions.True((basicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected loopback FILE_BASIC_INFORMATION attributes to include Hidden.");

                                ulong changeTime = unchecked((ulong)new DateTime(2020, 1, 2, 3, 4, 11, DateTimeKind.Utc).ToFileTimeUtc());
                                OpenCifsServerOperationResult<Smb2SetInfoResponse> changeTimeResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            ChangeTime = changeTime
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, changeTimeResult.Status, changeTimeResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> changedBasicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation changedBasicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, changedBasicQueryResult.Status, changedBasicQueryResult.Response));
                                TestAssertions.Equal(lastWriteTime, changedBasicInformation.LastWriteTime, "Unexpected loopback FILE_BASIC_INFORMATION last-write time after an explicit ChangeTime update.");
                                TestAssertions.Equal(changeTime, changedBasicInformation.ChangeTime, "Unexpected loopback FILE_BASIC_INFORMATION change time after an explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> networkOpenQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.NetworkOpenInformation));
                                FileNetworkOpenInformation networkOpenInformation = FileNetworkOpenInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, networkOpenQueryResult.Status, networkOpenQueryResult.Response));
                                TestAssertions.Equal(64UL, networkOpenInformation.AllocationSize, "Unexpected loopback FILE_NETWORK_OPEN_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, networkOpenInformation.EndOfFile, "Unexpected loopback FILE_NETWORK_OPEN_INFORMATION EOF size.");
                                TestAssertions.Equal(changeTime, networkOpenInformation.ChangeTime, "Unexpected loopback FILE_NETWORK_OPEN_INFORMATION change time after the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> internalInformationQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.InternalInformation));
                                FileInternalInformation internalInformation = FileInternalInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, internalInformationQueryResult.Status, internalInformationQueryResult.Response));
                                TestAssertions.Equal(openState.PersistentFileId, internalInformation.IndexNumber, "Unexpected loopback FILE_INTERNAL_INFORMATION index number.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> allInformationQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.File,
                                        FileInfoClass = FileInformationClass.AllInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileAllInformation allInformation = FileAllInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, allInformationQueryResult.Status, allInformationQueryResult.Response));
                                TestAssertions.Equal("notes.txt", allInformation.NameInformation.FileName, "Unexpected loopback FILE_ALL_INFORMATION name payload.");
                                TestAssertions.Equal(64UL, allInformation.StandardInformation.AllocationSize, "Unexpected loopback FILE_ALL_INFORMATION allocation size.");
                                TestAssertions.Equal(12UL, allInformation.StandardInformation.EndOfFile, "Unexpected loopback FILE_ALL_INFORMATION EOF size.");
                                TestAssertions.Equal(changeTime, allInformation.BasicInformation.ChangeTime, "Unexpected loopback FILE_ALL_INFORMATION change time after the explicit ChangeTime update.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSizeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsSizeInformation fileSystemSizeInformation = FileFsSizeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemSizeQueryResult.Status, fileSystemSizeQueryResult.Response));
                                TestAssertions.True(fileSystemSizeInformation.TotalAllocationUnits >= fileSystemSizeInformation.AvailableAllocationUnits, "Expected loopback FILE_FS_SIZE_INFORMATION total allocation units to be at least the available count.");
                                TestAssertions.True(fileSystemSizeInformation.SectorsPerAllocationUnit > 0, "Expected loopback FILE_FS_SIZE_INFORMATION sectors per allocation unit to be positive.");
                                TestAssertions.True(fileSystemSizeInformation.BytesPerSector > 0, "Expected loopback FILE_FS_SIZE_INFORMATION bytes per sector to be positive.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemVolumeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.VolumeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsVolumeInformation fileSystemVolumeInformation = FileFsVolumeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemVolumeQueryResult.Status, fileSystemVolumeQueryResult.Response));
                                TestAssertions.True(fileSystemVolumeInformation.VolumeSerialNumber != 0, "Expected loopback FILE_FS_VOLUME_INFORMATION serial numbers to be populated.");
                                TestAssertions.True(fileSystemVolumeInformation.VolumeLabel.Length != 0, "Expected loopback FILE_FS_VOLUME_INFORMATION labels to be non-empty.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemAttributeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.AttributeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsAttributeInformation fileSystemAttributeInformation = FileFsAttributeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemAttributeQueryResult.Status, fileSystemAttributeQueryResult.Response));
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.CasePreservedNames) != 0, "Expected loopback FILE_FS_ATTRIBUTE_INFORMATION to preserve filename casing.");
                                TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.UnicodeOnDisk) != 0, "Expected loopback FILE_FS_ATTRIBUTE_INFORMATION to advertise Unicode support.");
                                TestAssertions.True(fileSystemAttributeInformation.FileSystemName.Length != 0, "Expected loopback FILE_FS_ATTRIBUTE_INFORMATION filesystem names to be non-empty.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemDeviceQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.DeviceInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsDeviceInformation fileSystemDeviceInformation = FileFsDeviceInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemDeviceQueryResult.Status, fileSystemDeviceQueryResult.Response));
                                TestAssertions.Equal(FileSystemDeviceType.Disk, fileSystemDeviceInformation.DeviceType, "Expected loopback FILE_FS_DEVICE_INFORMATION to identify a disk-backed share.");
                                TestAssertions.True((fileSystemDeviceInformation.Characteristics & FileSystemDeviceCharacteristics.RemoteDevice) != 0, "Expected loopback FILE_FS_DEVICE_INFORMATION to advertise a remote device.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemFullSizeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.FullSizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsFullSizeInformation fileSystemFullSizeInformation = FileFsFullSizeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemFullSizeQueryResult.Status, fileSystemFullSizeQueryResult.Response));
                                TestAssertions.True(fileSystemFullSizeInformation.TotalAllocationUnits >= fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected loopback FILE_FS_FULL_SIZE_INFORMATION total allocation units to be at least the available count.");
                                TestAssertions.Equal(fileSystemFullSizeInformation.CallerAvailableAllocationUnits, fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected loopback FILE_FS_FULL_SIZE_INFORMATION caller and actual availability to match for the bounded slice.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSectorSizeQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    new Smb2QueryInfoRequest
                                    {
                                        InfoType = Smb2InfoType.FileSystem,
                                        FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SectorSizeInformation,
                                        OutputBufferLength = 512,
                                        PersistentFileId = openState.PersistentFileId,
                                        VolatileFileId = openState.VolatileFileId,
                                        InputBuffer = Array.Empty<byte>()
                                    });
                                FileFsSectorSizeInformation fileSystemSectorSizeInformation = FileFsSectorSizeInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, fileSystemSectorSizeQueryResult.Status, fileSystemSectorSizeQueryResult.Response));
                                TestAssertions.True(fileSystemSectorSizeInformation.LogicalBytesPerSector > 0, "Expected loopback FILE_FS_SECTOR_SIZE_INFORMATION logical bytes per sector to be positive.");
                                TestAssertions.True((fileSystemSectorSizeInformation.Flags & FileSystemSectorSizeFlags.AlignedDevice) != 0, "Expected loopback FILE_FS_SECTOR_SIZE_INFORMATION to advertise aligned devices.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyDisableResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue,
                                            LastAccessTime = UInt64.MaxValue,
                                            LastWriteTime = UInt64.MaxValue,
                                            ChangeTime = UInt64.MaxValue
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, stickyDisableResult.Status, stickyDisableResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> suppressedReadResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 0, minimumCount: 1));
                                client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, suppressedReadResult.Status, suppressedReadResult.Response);

                                OpenCifsServerOperationResult<Smb2WriteResponse> suppressedWriteResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, new byte[] { 0x41 }, 0));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, suppressedWriteResult.Status, suppressedWriteResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> suppressedBasicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation suppressedBasicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, suppressedBasicQueryResult.Status, suppressedBasicQueryResult.Response));
                                TestAssertions.Equal(creationTime, suppressedBasicInformation.CreationTime, "Expected loopback sticky timestamp directives to preserve creation time.");
                                TestAssertions.Equal(lastAccessTime, suppressedBasicInformation.LastAccessTime, "Expected loopback reads through a sticky-disabled handle to preserve last-access time.");
                                TestAssertions.Equal(lastWriteTime, suppressedBasicInformation.LastWriteTime, "Expected loopback writes through a sticky-disabled handle to preserve last-write time.");
                                TestAssertions.Equal(changeTime, suppressedBasicInformation.ChangeTime, "Expected loopback metadata mutations through a sticky-disabled handle to preserve change time.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyEnableResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        openState.PersistentFileId,
                                        openState.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            CreationTime = UInt64.MaxValue - 1,
                                            LastAccessTime = UInt64.MaxValue - 1,
                                            LastWriteTime = UInt64.MaxValue - 1,
                                            ChangeTime = UInt64.MaxValue - 1
                                        }));
                                client.ApplySetInfoResult(openState.PersistentFileId, openState.VolatileFileId, stickyEnableResult.Status, stickyEnableResult.Response);

                                OpenCifsServerOperationResult<Smb2ReadResponse> resumedReadResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(openState.PersistentFileId, openState.VolatileFileId, 1, 0, minimumCount: 1));
                                client.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, resumedReadResult.Status, resumedReadResult.Response);

                                OpenCifsServerOperationResult<Smb2WriteResponse> resumedWriteResult = server.HandleWrite(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateWriteRequest(openState.PersistentFileId, openState.VolatileFileId, new byte[] { 0x42 }, 1));
                                client.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, resumedWriteResult.Status, resumedWriteResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedBasicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation resumedBasicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, resumedBasicQueryResult.Status, resumedBasicQueryResult.Response));
                                TestAssertions.Equal(creationTime, resumedBasicInformation.CreationTime, "Expected loopback automatic timestamp updates to leave creation time unchanged.");
                                TestAssertions.True(resumedBasicInformation.LastAccessTime != lastAccessTime, "Expected loopback reads after sticky re-enable to advance last-access time.");
                                TestAssertions.True(resumedBasicInformation.LastWriteTime != lastWriteTime, "Expected loopback writes after sticky re-enable to advance last-write time.");
                                TestAssertions.True(resumedBasicInformation.ChangeTime != changeTime, "Expected loopback metadata mutations after sticky re-enable to advance change time.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedNetworkOpenQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.NetworkOpenInformation));
                                FileNetworkOpenInformation resumedNetworkOpenInformation = FileNetworkOpenInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, resumedNetworkOpenQueryResult.Status, resumedNetworkOpenQueryResult.Response));
                                TestAssertions.Equal(resumedBasicInformation.LastWriteTime, resumedNetworkOpenInformation.LastWriteTime, "Expected loopback FILE_NETWORK_OPEN_INFORMATION last-write time to match FILE_BASIC_INFORMATION after automatic updates resume.");
                                TestAssertions.Equal(resumedBasicInformation.ChangeTime, resumedNetworkOpenInformation.ChangeTime, "Expected loopback FILE_NETWORK_OPEN_INFORMATION change time to match FILE_BASIC_INFORMATION after automatic updates resume.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetRenameInfoRequest(openState.PersistentFileId, openState.VolatileFileId, "folder/renamed.txt"));
                                client.ApplySetRenameInfoResult(openState.PersistentFileId, openState.VolatileFileId, renameResult.Status, renameResult.Response, "folder/renamed.txt");
                                TestAssertions.Equal("folder\\renamed.txt", openState.Path, "Expected successful loopback rename to update the tracked open path.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> nameResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.NameInformation));
                                FileNameInformation fileNameInformation = FileNameInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, nameResult.Status, nameResult.Response));
                                TestAssertions.Equal("folder\\renamed.txt", fileNameInformation.FileName, "Unexpected loopback FILE_NAME_INFORMATION path after rename.");

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetDispositionInfoRequest(openState.PersistentFileId, openState.VolatileFileId, deletePending: true));
                                client.ApplySetDispositionInfoResult(openState.PersistentFileId, openState.VolatileFileId, dispositionResult.Status, dispositionResult.Response, deletePending: true);
                                TestAssertions.True(openState.IsDeletePending, "Expected successful loopback disposition updates to mark the tracked open delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> deletePendingResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(openState.PersistentFileId, openState.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation deletePendingInformation = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, deletePendingResult.Status, deletePendingResult.Response));
                                TestAssertions.True(deletePendingInformation.DeletePending, "Expected loopback FILE_DISPOSITION_INFORMATION to propagate to FILE_STANDARD_INFORMATION.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(openState.PersistentFileId, openState.VolatileFileId));
                                client.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeResult.Status, closeResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback metadata open after close.");
                                TestAssertions.False(File.Exists(Path.Combine(sharePath, "folder", "renamed.txt")), "Expected the delete-pending renamed file to be removed after the last close.");
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
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerRejectDispositionDeletePendingOnReadOnlyFilesAndDirectories",
                        displayName: "Client and server loopback reject FILE_DISPOSITION_INFORMATION delete-pending on read-only files and directories",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-file.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly);
                            string readOnlyDirectoryPath = Path.Combine(sharePath, "readonly-directory");
                            Directory.CreateDirectory(readOnlyDirectoryPath);
                            File.SetAttributes(readOnlyDirectoryPath, System.IO.FileAttributes.Directory | System.IO.FileAttributes.ReadOnly);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyFileOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-file.txt",
                                        desiredAccess: 0x80010000U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState readOnlyFileOpen = client.ApplyCreateResult(treeId, "readonly-file.txt", readOnlyFileOpenResult.Status, readOnlyFileOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyFileDisposition = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetDispositionInfoRequest(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, deletePending: true));
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetDispositionInfoResult(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, readOnlyFileDisposition.Status, readOnlyFileDisposition.Response, deletePending: true),
                                    "Expected loopback read-only file disposition failures to propagate through the client state surface.");
                                TestAssertions.False(readOnlyFileOpen.IsDeletePending, "Expected failed loopback read-only file disposition requests not to mark the tracked open delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyFileStandardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation readOnlyFileStandard = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, readOnlyFileStandardResult.Status, readOnlyFileStandardResult.Response));
                                TestAssertions.False(readOnlyFileStandard.DeletePending, "Expected loopback read-only file standard information not to report delete-pending after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyFileClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId));
                                client.ApplyCloseResult(readOnlyFileOpen.PersistentFileId, readOnlyFileOpen.VolatileFileId, readOnlyFileClose.Status, readOnlyFileClose.Response);
                                TestAssertions.True(File.Exists(readOnlyFilePath), "Expected the loopback read-only file to remain after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CreateResponse> readOnlyDirectoryOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-directory",
                                        desiredAccess: 0x80010000U,
                                        fileAttributes: OpenCIFS.Protocol.FileAttributes.Directory,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open,
                                        createOptions: Smb2CreateOptions.DirectoryFile));
                                OpenState readOnlyDirectoryOpen = client.ApplyCreateResult(treeId, "readonly-directory", readOnlyDirectoryOpenResult.Status, readOnlyDirectoryOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> readOnlyDirectoryDisposition = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetDispositionInfoRequest(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, deletePending: true));
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplySetDispositionInfoResult(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, readOnlyDirectoryDisposition.Status, readOnlyDirectoryDisposition.Response, deletePending: true),
                                    "Expected loopback read-only directory disposition failures to propagate through the client state surface.");
                                TestAssertions.False(readOnlyDirectoryOpen.IsDeletePending, "Expected failed loopback read-only directory disposition requests not to mark the tracked directory open delete-pending.");

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> readOnlyDirectoryStandardResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, FileInformationClass.StandardInformation));
                                FileStandardInformation readOnlyDirectoryStandard = FileStandardInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, readOnlyDirectoryStandardResult.Status, readOnlyDirectoryStandardResult.Response));
                                TestAssertions.False(readOnlyDirectoryStandard.DeletePending, "Expected loopback read-only directory standard information not to report delete-pending after the failed disposition request.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> readOnlyDirectoryClose = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId));
                                client.ApplyCloseResult(readOnlyDirectoryOpen.PersistentFileId, readOnlyDirectoryOpen.VolatileFileId, readOnlyDirectoryClose.Status, readOnlyDirectoryClose.Response);
                                TestAssertions.True(Directory.Exists(readOnlyDirectoryPath), "Expected the loopback read-only directory to remain after the failed disposition request.");
                                TestAssertions.Equal(0, client.OpenCount, "Expected the loopback read-only disposition slice to close all tracked opens.");
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(sharePath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.LoopbackMetadata",
                        caseId: "ClientAndServerApplyReadOnlyClearingMetadataUpdatesAndRejectAttributeOnlyFileReads",
                        displayName: "Client and server loopback apply read-only-clearing attribute-only FILE_BASIC_INFORMATION updates and reject file reads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsInteropSuite_" + Guid.NewGuid().ToString("N"));
                            Directory.CreateDirectory(sharePath);
                            string readOnlyFilePath = Path.Combine(sharePath, "readonly-attributes.txt");
                            File.WriteAllText(readOnlyFilePath, "seed");
                            File.SetAttributes(readOnlyFilePath, System.IO.FileAttributes.ReadOnly | System.IO.FileAttributes.Hidden);

                            try
                            {
                                OpenCifsServerHost server = CreateServerHost(sharePath);
                                OpenCifsClientSession client = CreateNegotiatedClient(server);
                                OpenCifsClientCredential credential = CreateCredential();
                                uint treeId = AuthenticateLoopbackSessionAndTree(server, client, credential);

                                OpenCifsServerOperationResult<Smb2CreateResponse> attributeOnlyOpenResult = server.HandleCreate(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCreateRequest(
                                        treeId,
                                        "readonly-attributes.txt",
                                        desiredAccess: 0x00000180U,
                                        shareAccess: 0x00000007U,
                                        createDisposition: Smb2CreateDisposition.Open));
                                OpenState attributeOnlyOpen = client.ApplyCreateResult(treeId, "readonly-attributes.txt", attributeOnlyOpenResult.Status, attributeOnlyOpenResult.Response);

                                OpenCifsServerOperationResult<Smb2SetInfoResponse> clearReadOnlyResult = server.HandleSetInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateSetBasicInfoRequest(
                                        attributeOnlyOpen.PersistentFileId,
                                        attributeOnlyOpen.VolatileFileId,
                                        new FileBasicInformation
                                        {
                                            FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                                        }));
                                client.ApplySetInfoResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, clearReadOnlyResult.Status, clearReadOnlyResult.Response);

                                OpenCifsServerOperationResult<Smb2QueryInfoResponse> basicQueryResult = server.HandleQueryInfo(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateQueryInfoRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, FileInformationClass.BasicInformation));
                                FileBasicInformation basicInformation = FileBasicInformation.ReadFrom(
                                    client.ApplyQueryInfoResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, basicQueryResult.Status, basicQueryResult.Response));
                                TestAssertions.False((basicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.ReadOnly) != 0, "Expected loopback FILE_BASIC_INFORMATION updates to clear the read-only attribute.");
                                TestAssertions.True((basicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected loopback FILE_BASIC_INFORMATION updates to preserve the hidden attribute.");

                                OpenCifsServerOperationResult<Smb2ReadResponse> deniedReadResult = server.HandleRead(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateReadRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, length: 1, offset: 0));
                                TestAssertions.Equal(NtStatus.AccessDenied, deniedReadResult.Status, "Expected loopback attribute-only metadata opens not to grant file-read data access.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => client.ApplyReadResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, deniedReadResult.Status, deniedReadResult.Response),
                                    "Expected loopback denied reads on attribute-only metadata opens to propagate through the client state surface.");
                                TestAssertions.False((File.GetAttributes(readOnlyFilePath) & System.IO.FileAttributes.ReadOnly) != 0, "Expected the loopback backing file to have its read-only attribute cleared.");

                                OpenCifsServerOperationResult<Smb2CloseResponse> attributeOnlyCloseResult = server.HandleClose(
                                    client.SessionId!.Value,
                                    treeId,
                                    client.CreateCloseRequest(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId));
                                client.ApplyCloseResult(attributeOnlyOpen.PersistentFileId, attributeOnlyOpen.VolatileFileId, attributeOnlyCloseResult.Status, attributeOnlyCloseResult.Response);
                                TestAssertions.Equal(0, client.OpenCount, "Expected the client to clear the loopback attribute-only metadata open after close.");
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
