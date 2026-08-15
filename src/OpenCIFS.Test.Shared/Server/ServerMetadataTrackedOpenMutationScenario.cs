namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.IO;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Server.Tests.Shared.ServerTestSupport;

    internal static class ServerMetadataTrackedOpenMutationScenario
    {
        internal static Task ExecuteAsync(CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            string sharePath = Path.Combine(Path.GetTempPath(), "OpenCifsServerSuite_" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(sharePath);
            Directory.CreateDirectory(Path.Combine(sharePath, "archive"));
            File.WriteAllText(Path.Combine(sharePath, "alpha.txt"), "seed");

            try
            {
                OpenCifsServerHost host = CreateServerHost(sharePath);
                AuthenticatedTreeContext treeContext = AuthenticateAndConnectTree(host);
                ulong sessionId = treeContext.SessionId;
                uint treeId = treeContext.TreeId;
                OpenCifsServerOperationResult<Smb2CreateResponse> createResult = OpenTrackedFile(host, sessionId, treeId);
                ulong creationTime = ToFileTimeUtc(2020, 1, 2, 3, 4, 4);
                ulong lastAccessTime = ToFileTimeUtc(2020, 1, 2, 3, 4, 5);
                ulong lastWriteTime = ToFileTimeUtc(2020, 1, 2, 3, 4, 6);
                ulong changeTime = ToFileTimeUtc(2020, 1, 2, 3, 4, 7);

                ApplyInitialMetadataMutations(host, sessionId, treeId, createResult.Response, creationTime, lastAccessTime, lastWriteTime);
                AssertTrackedOpenMetadataQueries(host, sessionId, treeId, createResult.Response, creationTime, lastAccessTime, lastWriteTime, changeTime);
                AssertTrackedOpenFileSystemQueries(host, sessionId, treeId, createResult.Response);
                AssertStickyTimestampSuppression(host, sessionId, treeId, createResult.Response, creationTime, lastAccessTime, lastWriteTime, changeTime);
                AssertStickyTimestampRestoration(host, sessionId, treeId, createResult.Response, creationTime, lastAccessTime, lastWriteTime, changeTime);
                AssertRenameDeletePendingAndClose(host, sessionId, treeId, createResult.Response, sharePath);
            }
            finally
            {
                if (Directory.Exists(sharePath))
                {
                    Directory.Delete(sharePath, recursive: true);
                }
            }

            return Task.CompletedTask;
        }

        private static OpenCifsServerOperationResult<Smb2CreateResponse> OpenTrackedFile(OpenCifsServerHost host, ulong sessionId, uint treeId)
        {
            OpenCifsServerOperationResult<Smb2CreateResponse> createResult = host.HandleCreate(
                sessionId,
                treeId,
                CreateFileCreateRequest("alpha.txt", Smb2CreateDisposition.Open, desiredAccess: 0xC0010000U, shareAccess: 0x00000007U));
            TestAssertions.Equal(NtStatus.Success, createResult.Status, "Expected metadata test open to succeed.");
            return createResult;
        }

        private static void ApplyInitialMetadataMutations(
            OpenCifsServerHost host,
            ulong sessionId,
            uint treeId,
            Smb2CreateResponse createResponse,
            ulong creationTime,
            ulong lastAccessTime,
            ulong lastWriteTime)
        {
            OpenCifsServerOperationResult<Smb2SetInfoResponse> allocationResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.AllocationInformation,
                    new FileAllocationInformation
                    {
                        AllocationSize = 64
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, allocationResult.Status, "Expected FILE_ALLOCATION_INFORMATION to succeed.");

            OpenCifsServerOperationResult<Smb2SetInfoResponse> endOfFileResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.EndOfFileInformation,
                    new FileEndOfFileInformation
                    {
                        EndOfFile = 12
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, endOfFileResult.Status, "Expected FILE_END_OF_FILE_INFORMATION to succeed.");

            OpenCifsServerOperationResult<Smb2SetInfoResponse> basicResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.BasicInformation,
                    new FileBasicInformation
                    {
                        CreationTime = creationTime,
                        LastAccessTime = lastAccessTime,
                        LastWriteTime = lastWriteTime,
                        FileAttributes = OpenCIFS.Protocol.FileAttributes.Hidden
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, basicResult.Status, "Expected FILE_BASIC_INFORMATION to succeed.");
        }

        private static void AssertTrackedOpenMetadataQueries(
            OpenCifsServerHost host,
            ulong sessionId,
            uint treeId,
            Smb2CreateResponse createResponse,
            ulong creationTime,
            ulong lastAccessTime,
            ulong lastWriteTime,
            ulong changeTime)
        {
            OpenCifsServerOperationResult<Smb2QueryInfoResponse> nameResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.NameInformation));
            TestAssertions.Equal(NtStatus.Success, nameResult.Status, "Expected FILE_NAME_INFORMATION query to succeed.");
            FileNameInformation initialName = FileNameInformation.ReadFrom(nameResult.Response.OutputBuffer);
            TestAssertions.Equal("alpha.txt", initialName.FileName, "Unexpected initial FILE_NAME_INFORMATION path.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> standardResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.StandardInformation));
            TestAssertions.Equal(NtStatus.Success, standardResult.Status, "Expected FILE_STANDARD_INFORMATION query to succeed.");
            FileStandardInformation standardInformation = FileStandardInformation.ReadFrom(standardResult.Response.OutputBuffer);
            TestAssertions.Equal(64UL, standardInformation.AllocationSize, "Unexpected FILE_STANDARD_INFORMATION allocation size.");
            TestAssertions.Equal(12UL, standardInformation.EndOfFile, "Unexpected FILE_STANDARD_INFORMATION EOF size.");
            TestAssertions.False(standardInformation.DeletePending, "The open should not be delete-pending before FILE_DISPOSITION_INFORMATION runs.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> basicQueryResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.BasicInformation));
            TestAssertions.Equal(NtStatus.Success, basicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query to succeed.");
            FileBasicInformation queriedBasicInformation = FileBasicInformation.ReadFrom(basicQueryResult.Response.OutputBuffer);
            TestAssertions.Equal(creationTime, queriedBasicInformation.CreationTime, "Unexpected FILE_BASIC_INFORMATION creation time after update.");
            TestAssertions.Equal(lastAccessTime, queriedBasicInformation.LastAccessTime, "Unexpected FILE_BASIC_INFORMATION last-access time after update.");
            TestAssertions.Equal(lastWriteTime, queriedBasicInformation.LastWriteTime, "Unexpected FILE_BASIC_INFORMATION last-write time after update.");
            TestAssertions.True((queriedBasicInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected FILE_BASIC_INFORMATION attributes to include Hidden.");

            OpenCifsServerOperationResult<Smb2SetInfoResponse> changeTimeResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.BasicInformation,
                    new FileBasicInformation
                    {
                        ChangeTime = changeTime
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, changeTimeResult.Status, "Expected ChangeTime-only FILE_BASIC_INFORMATION updates to succeed in the current slice.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> changedBasicQueryResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.BasicInformation));
            TestAssertions.Equal(NtStatus.Success, changedBasicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query after a ChangeTime-only update to succeed.");
            FileBasicInformation changedBasicInformation = FileBasicInformation.ReadFrom(changedBasicQueryResult.Response.OutputBuffer);
            TestAssertions.Equal(lastWriteTime, changedBasicInformation.LastWriteTime, "Expected explicit ChangeTime updates to preserve FILE_BASIC_INFORMATION last-write time.");
            TestAssertions.Equal(changeTime, changedBasicInformation.ChangeTime, "Expected FILE_BASIC_INFORMATION queries to reflect the explicit ChangeTime update.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> networkOpenResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.NetworkOpenInformation));
            TestAssertions.Equal(NtStatus.Success, networkOpenResult.Status, "Expected FILE_NETWORK_OPEN_INFORMATION query to succeed.");
            FileNetworkOpenInformation networkOpenInformation = FileNetworkOpenInformation.ReadFrom(networkOpenResult.Response.OutputBuffer);
            TestAssertions.Equal(64UL, networkOpenInformation.AllocationSize, "Unexpected FILE_NETWORK_OPEN_INFORMATION allocation size.");
            TestAssertions.Equal(12UL, networkOpenInformation.EndOfFile, "Unexpected FILE_NETWORK_OPEN_INFORMATION EOF size.");
            TestAssertions.True((networkOpenInformation.FileAttributes & OpenCIFS.Protocol.FileAttributes.Hidden) != 0, "Expected FILE_NETWORK_OPEN_INFORMATION attributes to include Hidden.");
            TestAssertions.Equal(changeTime, networkOpenInformation.ChangeTime, "Expected FILE_NETWORK_OPEN_INFORMATION change time to reflect the explicit ChangeTime update.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> internalInformationResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.InternalInformation, outputBufferLength: 8));
            TestAssertions.Equal(NtStatus.Success, internalInformationResult.Status, "Expected FILE_INTERNAL_INFORMATION query to succeed.");
            FileInternalInformation internalInformation = FileInternalInformation.ReadFrom(internalInformationResult.Response.OutputBuffer);
            TestAssertions.Equal(createResponse.PersistentFileId, internalInformation.IndexNumber, "Expected FILE_INTERNAL_INFORMATION to return the stable open index number.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> allInformationResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.AllInformation));
            TestAssertions.Equal(NtStatus.Success, allInformationResult.Status, "Expected FILE_ALL_INFORMATION query to succeed.");
            FileAllInformation allInformation = FileAllInformation.ReadFrom(allInformationResult.Response.OutputBuffer);
            TestAssertions.Equal("alpha.txt", allInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name payload.");
            TestAssertions.Equal(64UL, allInformation.StandardInformation.AllocationSize, "Unexpected FILE_ALL_INFORMATION allocation size.");
            TestAssertions.Equal(12UL, allInformation.StandardInformation.EndOfFile, "Unexpected FILE_ALL_INFORMATION EOF size.");
            TestAssertions.Equal(changeTime, allInformation.BasicInformation.ChangeTime, "Expected FILE_ALL_INFORMATION change time to reflect the explicit ChangeTime update.");
        }

        private static void AssertTrackedOpenFileSystemQueries(OpenCifsServerHost host, ulong sessionId, uint treeId, Smb2CreateResponse createResponse)
        {
            OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSizeResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.FileSystem, (FileInformationClass)(byte)FileSystemInformationClass.SizeInformation));
            TestAssertions.Equal(NtStatus.Success, fileSystemSizeResult.Status, "Expected FILE_FS_SIZE_INFORMATION query to succeed.");
            FileFsSizeInformation fileSystemSizeInformation = FileFsSizeInformation.ReadFrom(fileSystemSizeResult.Response.OutputBuffer);
            TestAssertions.True(fileSystemSizeInformation.TotalAllocationUnits >= fileSystemSizeInformation.AvailableAllocationUnits, "Expected FILE_FS_SIZE_INFORMATION total allocation units to be at least the available count.");
            TestAssertions.True(fileSystemSizeInformation.SectorsPerAllocationUnit > 0, "Expected FILE_FS_SIZE_INFORMATION sectors per allocation unit to be positive.");
            TestAssertions.True(fileSystemSizeInformation.BytesPerSector > 0, "Expected FILE_FS_SIZE_INFORMATION bytes per sector to be positive.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemVolumeResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.FileSystem, (FileInformationClass)(byte)FileSystemInformationClass.VolumeInformation));
            TestAssertions.Equal(NtStatus.Success, fileSystemVolumeResult.Status, "Expected FILE_FS_VOLUME_INFORMATION query to succeed.");
            FileFsVolumeInformation fileSystemVolumeInformation = FileFsVolumeInformation.ReadFrom(fileSystemVolumeResult.Response.OutputBuffer);
            TestAssertions.True(fileSystemVolumeInformation.VolumeSerialNumber != 0, "Expected FILE_FS_VOLUME_INFORMATION serial numbers to be populated.");
            TestAssertions.True(fileSystemVolumeInformation.VolumeLabel.Length != 0, "Expected FILE_FS_VOLUME_INFORMATION labels to be non-empty.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemAttributeResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.FileSystem, (FileInformationClass)(byte)FileSystemInformationClass.AttributeInformation));
            TestAssertions.Equal(NtStatus.Success, fileSystemAttributeResult.Status, "Expected FILE_FS_ATTRIBUTE_INFORMATION query to succeed.");
            FileFsAttributeInformation fileSystemAttributeInformation = FileFsAttributeInformation.ReadFrom(fileSystemAttributeResult.Response.OutputBuffer);
            TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.CasePreservedNames) != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION to preserve filename casing.");
            TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.UnicodeOnDisk) != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION to advertise Unicode support.");
            TestAssertions.True((fileSystemAttributeInformation.FileSystemAttributes & FileSystemAttributesFlags.PersistentAcls) != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION to advertise persistent ACL support.");
            TestAssertions.True(fileSystemAttributeInformation.MaximumComponentNameLength > 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION maximum component lengths to be positive.");
            TestAssertions.True(fileSystemAttributeInformation.FileSystemName.Length != 0, "Expected FILE_FS_ATTRIBUTE_INFORMATION filesystem names to be non-empty.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemDeviceResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.FileSystem, (FileInformationClass)(byte)FileSystemInformationClass.DeviceInformation));
            TestAssertions.Equal(NtStatus.Success, fileSystemDeviceResult.Status, "Expected FILE_FS_DEVICE_INFORMATION query to succeed.");
            FileFsDeviceInformation fileSystemDeviceInformation = FileFsDeviceInformation.ReadFrom(fileSystemDeviceResult.Response.OutputBuffer);
            TestAssertions.Equal(FileSystemDeviceType.Disk, fileSystemDeviceInformation.DeviceType, "Expected FILE_FS_DEVICE_INFORMATION to identify a disk-backed share.");
            TestAssertions.True((fileSystemDeviceInformation.Characteristics & FileSystemDeviceCharacteristics.RemoteDevice) != 0, "Expected FILE_FS_DEVICE_INFORMATION to advertise a remote device.");
            TestAssertions.True((fileSystemDeviceInformation.Characteristics & FileSystemDeviceCharacteristics.DeviceIsMounted) != 0, "Expected FILE_FS_DEVICE_INFORMATION to advertise a mounted device.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemFullSizeResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.FileSystem, (FileInformationClass)(byte)FileSystemInformationClass.FullSizeInformation));
            TestAssertions.Equal(NtStatus.Success, fileSystemFullSizeResult.Status, "Expected FILE_FS_FULL_SIZE_INFORMATION query to succeed.");
            FileFsFullSizeInformation fileSystemFullSizeInformation = FileFsFullSizeInformation.ReadFrom(fileSystemFullSizeResult.Response.OutputBuffer);
            TestAssertions.True(fileSystemFullSizeInformation.TotalAllocationUnits >= fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected FILE_FS_FULL_SIZE_INFORMATION total allocation units to be at least the available count.");
            TestAssertions.Equal(fileSystemFullSizeInformation.CallerAvailableAllocationUnits, fileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Expected FILE_FS_FULL_SIZE_INFORMATION caller and actual availability to match for the bounded slice.");
            TestAssertions.True(fileSystemFullSizeInformation.BytesPerSector > 0, "Expected FILE_FS_FULL_SIZE_INFORMATION bytes per sector to be positive.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> fileSystemSectorSizeResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.FileSystem, (FileInformationClass)(byte)FileSystemInformationClass.SectorSizeInformation));
            TestAssertions.Equal(NtStatus.Success, fileSystemSectorSizeResult.Status, "Expected FILE_FS_SECTOR_SIZE_INFORMATION query to succeed.");
            FileFsSectorSizeInformation fileSystemSectorSizeInformation = FileFsSectorSizeInformation.ReadFrom(fileSystemSectorSizeResult.Response.OutputBuffer);
            TestAssertions.True(fileSystemSectorSizeInformation.LogicalBytesPerSector > 0, "Expected FILE_FS_SECTOR_SIZE_INFORMATION logical bytes per sector to be positive.");
            TestAssertions.True(fileSystemSectorSizeInformation.PhysicalBytesPerSectorForAtomicity >= fileSystemSectorSizeInformation.LogicalBytesPerSector, "Expected FILE_FS_SECTOR_SIZE_INFORMATION atomicity bytes per sector to be at least the logical size.");
            TestAssertions.True((fileSystemSectorSizeInformation.Flags & FileSystemSectorSizeFlags.AlignedDevice) != 0, "Expected FILE_FS_SECTOR_SIZE_INFORMATION to advertise aligned devices.");
        }

        private static void AssertStickyTimestampSuppression(
            OpenCifsServerHost host,
            ulong sessionId,
            uint treeId,
            Smb2CreateResponse createResponse,
            ulong creationTime,
            ulong lastAccessTime,
            ulong lastWriteTime,
            ulong changeTime)
        {
            OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyDisableResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.BasicInformation,
                    new FileBasicInformation
                    {
                        CreationTime = UInt64.MaxValue,
                        LastAccessTime = UInt64.MaxValue,
                        LastWriteTime = UInt64.MaxValue,
                        ChangeTime = UInt64.MaxValue
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, stickyDisableResult.Status, "Expected sticky FILE_BASIC_INFORMATION disable directives to succeed.");

            OpenCifsServerOperationResult<Smb2ReadResponse> suppressedReadResult = host.HandleRead(sessionId, treeId, CreateReadRequest(createResponse, offset: 0, length: 1));
            TestAssertions.Equal(NtStatus.Success, suppressedReadResult.Status, "Expected reads to succeed while timestamp updates are disabled.");

            OpenCifsServerOperationResult<Smb2WriteResponse> suppressedWriteResult = host.HandleWrite(sessionId, treeId, CreateWriteRequest(createResponse, offset: 0, data: new byte[] { 0x41 }));
            TestAssertions.Equal(NtStatus.Success, suppressedWriteResult.Status, "Expected writes to succeed while timestamp updates are disabled.");

            OpenCifsServerOperationResult<Smb2SetInfoResponse> suppressedAllocationResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.AllocationInformation,
                    new FileAllocationInformation
                    {
                        AllocationSize = 96
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, suppressedAllocationResult.Status, "Expected FILE_ALLOCATION_INFORMATION to succeed while timestamp updates are disabled.");

            OpenCifsServerOperationResult<Smb2SetInfoResponse> suppressedEndOfFileResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.EndOfFileInformation,
                    new FileEndOfFileInformation
                    {
                        EndOfFile = 16
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, suppressedEndOfFileResult.Status, "Expected FILE_END_OF_FILE_INFORMATION to succeed while timestamp updates are disabled.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> suppressedStandardResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.StandardInformation));
            TestAssertions.Equal(NtStatus.Success, suppressedStandardResult.Status, "Expected FILE_STANDARD_INFORMATION query after disabled timestamp updates to succeed.");
            FileStandardInformation suppressedStandardInformation = FileStandardInformation.ReadFrom(suppressedStandardResult.Response.OutputBuffer);
            TestAssertions.Equal(96UL, suppressedStandardInformation.AllocationSize, "Expected allocation updates to remain visible while timestamps are pinned.");
            TestAssertions.Equal(16UL, suppressedStandardInformation.EndOfFile, "Expected EOF updates to remain visible while timestamps are pinned.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> suppressedBasicQueryResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.BasicInformation));
            TestAssertions.Equal(NtStatus.Success, suppressedBasicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query after disabled timestamp updates to succeed.");
            FileBasicInformation suppressedBasicInformation = FileBasicInformation.ReadFrom(suppressedBasicQueryResult.Response.OutputBuffer);
            TestAssertions.Equal(creationTime, suppressedBasicInformation.CreationTime, "Expected sticky FILE_BASIC_INFORMATION directives to preserve creation time.");
            TestAssertions.Equal(lastAccessTime, suppressedBasicInformation.LastAccessTime, "Expected reads through a sticky-disabled handle to preserve last-access time.");
            TestAssertions.Equal(lastWriteTime, suppressedBasicInformation.LastWriteTime, "Expected writes through a sticky-disabled handle to preserve last-write time.");
            TestAssertions.Equal(changeTime, suppressedBasicInformation.ChangeTime, "Expected metadata mutations through a sticky-disabled handle to preserve change time.");
        }

        private static void AssertStickyTimestampRestoration(
            OpenCifsServerHost host,
            ulong sessionId,
            uint treeId,
            Smb2CreateResponse createResponse,
            ulong creationTime,
            ulong lastAccessTime,
            ulong lastWriteTime,
            ulong changeTime)
        {
            OpenCifsServerOperationResult<Smb2SetInfoResponse> stickyEnableResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.BasicInformation,
                    new FileBasicInformation
                    {
                        CreationTime = UInt64.MaxValue - 1,
                        LastAccessTime = UInt64.MaxValue - 1,
                        LastWriteTime = UInt64.MaxValue - 1,
                        ChangeTime = UInt64.MaxValue - 1
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, stickyEnableResult.Status, "Expected sticky FILE_BASIC_INFORMATION enable directives to succeed.");

            OpenCifsServerOperationResult<Smb2ReadResponse> resumedReadResult = host.HandleRead(sessionId, treeId, CreateReadRequest(createResponse, offset: 0, length: 1));
            TestAssertions.Equal(NtStatus.Success, resumedReadResult.Status, "Expected reads to succeed after re-enabling automatic timestamp updates.");

            OpenCifsServerOperationResult<Smb2WriteResponse> resumedWriteResult = host.HandleWrite(sessionId, treeId, CreateWriteRequest(createResponse, offset: 1, data: new byte[] { 0x42 }));
            TestAssertions.Equal(NtStatus.Success, resumedWriteResult.Status, "Expected writes to succeed after re-enabling automatic timestamp updates.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedBasicQueryResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.BasicInformation));
            TestAssertions.Equal(NtStatus.Success, resumedBasicQueryResult.Status, "Expected FILE_BASIC_INFORMATION query after re-enabled timestamp updates to succeed.");
            FileBasicInformation resumedBasicInformation = FileBasicInformation.ReadFrom(resumedBasicQueryResult.Response.OutputBuffer);
            TestAssertions.Equal(creationTime, resumedBasicInformation.CreationTime, "Expected automatic timestamp updates to leave creation time unchanged.");
            TestAssertions.True(resumedBasicInformation.LastAccessTime != lastAccessTime, "Expected reads after sticky re-enable to advance last-access time.");
            TestAssertions.True(resumedBasicInformation.LastWriteTime != lastWriteTime, "Expected writes after sticky re-enable to advance last-write time.");
            TestAssertions.True(resumedBasicInformation.ChangeTime != changeTime, "Expected metadata mutations after sticky re-enable to advance change time.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> resumedNetworkOpenResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.NetworkOpenInformation));
            TestAssertions.Equal(NtStatus.Success, resumedNetworkOpenResult.Status, "Expected FILE_NETWORK_OPEN_INFORMATION query after re-enabled timestamp updates to succeed.");
            FileNetworkOpenInformation resumedNetworkOpenInformation = FileNetworkOpenInformation.ReadFrom(resumedNetworkOpenResult.Response.OutputBuffer);
            TestAssertions.Equal(resumedBasicInformation.LastWriteTime, resumedNetworkOpenInformation.LastWriteTime, "Expected FILE_NETWORK_OPEN_INFORMATION last-write time to match FILE_BASIC_INFORMATION after automatic updates resume.");
            TestAssertions.Equal(resumedBasicInformation.ChangeTime, resumedNetworkOpenInformation.ChangeTime, "Expected FILE_NETWORK_OPEN_INFORMATION change time to match FILE_BASIC_INFORMATION after automatic updates resume.");
        }

        private static void AssertRenameDeletePendingAndClose(
            OpenCifsServerHost host,
            ulong sessionId,
            uint treeId,
            Smb2CreateResponse createResponse,
            string sharePath)
        {
            OpenCifsServerOperationResult<Smb2SetInfoResponse> renameResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.RenameInformation,
                    new FileRenameInformationType2
                    {
                        ReplaceIfExists = false,
                        RootDirectory = 0,
                        FileName = "archive\\beta.txt"
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, renameResult.Status, "Expected FILE_RENAME_INFORMATION_TYPE_2 to succeed.");
            TestAssertions.False(File.Exists(Path.Combine(sharePath, "alpha.txt")), "Expected the original file path to be removed after rename.");
            TestAssertions.True(File.Exists(Path.Combine(sharePath, "archive", "beta.txt")), "Expected the renamed file path to exist after rename.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> renamedNameResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.NameInformation));
            TestAssertions.Equal(NtStatus.Success, renamedNameResult.Status, "Expected FILE_NAME_INFORMATION query after rename to succeed.");
            FileNameInformation renamedName = FileNameInformation.ReadFrom(renamedNameResult.Response.OutputBuffer);
            TestAssertions.Equal("archive\\beta.txt", renamedName.FileName, "Unexpected FILE_NAME_INFORMATION path after rename.");

            OpenCifsServerOperationResult<Smb2SetInfoResponse> dispositionResult = host.HandleSetInfo(
                sessionId,
                treeId,
                CreateSetInfoRequest(
                    createResponse,
                    FileInformationClass.DispositionInformation,
                    new FileDispositionInformation
                    {
                        DeletePending = true
                    }.ToByteArray()));
            TestAssertions.Equal(NtStatus.Success, dispositionResult.Status, "Expected FILE_DISPOSITION_INFORMATION to succeed.");

            OpenCifsServerOperationResult<Smb2QueryInfoResponse> deletePendingResult = host.HandleQueryInfo(
                sessionId,
                treeId,
                CreateQueryInfoRequest(createResponse, Smb2InfoType.File, FileInformationClass.StandardInformation));
            TestAssertions.Equal(NtStatus.Success, deletePendingResult.Status, "Expected FILE_STANDARD_INFORMATION query after disposition to succeed.");
            FileStandardInformation deletePendingInformation = FileStandardInformation.ReadFrom(deletePendingResult.Response.OutputBuffer);
            TestAssertions.True(deletePendingInformation.DeletePending, "Expected FILE_DISPOSITION_INFORMATION to mark the open delete-pending.");

            OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = host.HandleClose(sessionId, treeId, CreateCloseRequest(createResponse));
            TestAssertions.Equal(NtStatus.Success, closeResult.Status, "Expected metadata test close to succeed.");
            TestAssertions.False(File.Exists(Path.Combine(sharePath, "archive", "beta.txt")), "Expected the delete-pending renamed file to be removed on last close.");
        }

        private static Smb2QueryInfoRequest CreateQueryInfoRequest(
            Smb2CreateResponse createResponse,
            Smb2InfoType infoType,
            FileInformationClass fileInfoClass,
            uint outputBufferLength = 512)
        {
            return new Smb2QueryInfoRequest
            {
                InfoType = infoType,
                FileInfoClass = fileInfoClass,
                OutputBufferLength = outputBufferLength,
                PersistentFileId = createResponse.PersistentFileId,
                VolatileFileId = createResponse.VolatileFileId,
                InputBuffer = Array.Empty<byte>()
            };
        }

        private static Smb2SetInfoRequest CreateSetInfoRequest(Smb2CreateResponse createResponse, FileInformationClass fileInfoClass, byte[] buffer)
        {
            return new Smb2SetInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = fileInfoClass,
                PersistentFileId = createResponse.PersistentFileId,
                VolatileFileId = createResponse.VolatileFileId,
                Buffer = buffer
            };
        }

        private static Smb2ReadRequest CreateReadRequest(Smb2CreateResponse createResponse, ulong offset, uint length)
        {
            return new Smb2ReadRequest
            {
                Length = length,
                Offset = offset,
                PersistentFileId = createResponse.PersistentFileId,
                VolatileFileId = createResponse.VolatileFileId,
                MinimumCount = length,
                Channel = 0,
                RemainingBytes = 0,
                ReadChannelInfo = Array.Empty<byte>()
            };
        }

        private static Smb2WriteRequest CreateWriteRequest(Smb2CreateResponse createResponse, ulong offset, byte[] data)
        {
            return new Smb2WriteRequest
            {
                Offset = offset,
                PersistentFileId = createResponse.PersistentFileId,
                VolatileFileId = createResponse.VolatileFileId,
                Channel = 0,
                RemainingBytes = 0,
                Flags = Smb2WriteFlags.None,
                DataBuffer = data,
                WriteChannelInfo = Array.Empty<byte>()
            };
        }

        private static Smb2CloseRequest CreateCloseRequest(Smb2CreateResponse createResponse)
        {
            return new Smb2CloseRequest
            {
                PersistentFileId = createResponse.PersistentFileId,
                VolatileFileId = createResponse.VolatileFileId
            };
        }

        private static ulong ToFileTimeUtc(int year, int month, int day, int hour, int minute, int second)
        {
            return unchecked((ulong)new DateTime(year, month, day, hour, minute, second, DateTimeKind.Utc).ToFileTimeUtc());
        }
    }
}
