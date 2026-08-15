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
    internal static class MetadataSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Metadata",
                displayName: "SMB2 metadata codecs and validators",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Metadata",
                        caseId: "MetadataModelsRoundTrip",
                        displayName: "SMB2 metadata models, directory-enumeration payloads, and compound trimming round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            FileBasicInformation basicInformation = new FileBasicInformation
                            {
                                CreationTime = 0x0102030405060708UL,
                                LastAccessTime = 0x1112131415161718UL,
                                LastWriteTime = 0x2122232425262728UL,
                                ChangeTime = 0x3132333435363738UL,
                                FileAttributes = ProtocolFileAttributes.Hidden | ProtocolFileAttributes.Archive
                            };
                            FileBasicInformation parsedBasicInformation = FileBasicInformation.ReadFrom(basicInformation.ToByteArray());
                            TestAssertions.Equal(basicInformation.CreationTime, parsedBasicInformation.CreationTime, "Unexpected FILE_BASIC_INFORMATION creation time.");
                            TestAssertions.Equal(basicInformation.LastAccessTime, parsedBasicInformation.LastAccessTime, "Unexpected FILE_BASIC_INFORMATION last-access time.");
                            TestAssertions.Equal(basicInformation.LastWriteTime, parsedBasicInformation.LastWriteTime, "Unexpected FILE_BASIC_INFORMATION last-write time.");
                            TestAssertions.Equal(basicInformation.ChangeTime, parsedBasicInformation.ChangeTime, "Unexpected FILE_BASIC_INFORMATION change time.");
                            TestAssertions.Equal(basicInformation.FileAttributes, parsedBasicInformation.FileAttributes, "Unexpected FILE_BASIC_INFORMATION attributes.");

                            FileStandardInformation standardInformation = new FileStandardInformation
                            {
                                AllocationSize = 4096,
                                EndOfFile = 1536,
                                NumberOfLinks = 1,
                                DeletePending = true,
                                Directory = false
                            };
                            FileStandardInformation parsedStandardInformation = FileStandardInformation.ReadFrom(standardInformation.ToByteArray());
                            TestAssertions.Equal(standardInformation.AllocationSize, parsedStandardInformation.AllocationSize, "Unexpected FILE_STANDARD_INFORMATION allocation size.");
                            TestAssertions.Equal(standardInformation.EndOfFile, parsedStandardInformation.EndOfFile, "Unexpected FILE_STANDARD_INFORMATION EOF size.");
                            TestAssertions.True(parsedStandardInformation.DeletePending, "Expected FILE_STANDARD_INFORMATION delete-pending to round-trip.");

                            FileNameInformation fileNameInformation = new FileNameInformation
                            {
                                FileName = "folder\\notes.txt"
                            };
                            FileNameInformation parsedFileNameInformation = FileNameInformation.ReadFrom(fileNameInformation.ToByteArray());
                            TestAssertions.Equal(fileNameInformation.FileName, parsedFileNameInformation.FileName, "Unexpected FILE_NAME_INFORMATION path.");

                            FileNetworkOpenInformation networkOpenInformation = new FileNetworkOpenInformation
                            {
                                CreationTime = basicInformation.CreationTime,
                                LastAccessTime = basicInformation.LastAccessTime,
                                LastWriteTime = basicInformation.LastWriteTime,
                                ChangeTime = basicInformation.ChangeTime,
                                AllocationSize = 8192,
                                EndOfFile = 2048,
                                FileAttributes = ProtocolFileAttributes.ReadOnly
                            };
                            FileNetworkOpenInformation parsedNetworkOpenInformation = FileNetworkOpenInformation.ReadFrom(networkOpenInformation.ToByteArray());
                            TestAssertions.Equal(networkOpenInformation.AllocationSize, parsedNetworkOpenInformation.AllocationSize, "Unexpected FILE_NETWORK_OPEN_INFORMATION allocation size.");
                            TestAssertions.Equal(networkOpenInformation.EndOfFile, parsedNetworkOpenInformation.EndOfFile, "Unexpected FILE_NETWORK_OPEN_INFORMATION EOF size.");
                            TestAssertions.Equal(networkOpenInformation.FileAttributes, parsedNetworkOpenInformation.FileAttributes, "Unexpected FILE_NETWORK_OPEN_INFORMATION attributes.");

                            FileAllInformation allInformation = new FileAllInformation
                            {
                                BasicInformation = basicInformation,
                                StandardInformation = standardInformation,
                                InternalIndexNumber = 0x0102030405060708UL,
                                EaSize = 12,
                                AccessFlags = 0x0012019FU,
                                CurrentByteOffset = 128,
                                Mode = 0,
                                AlignmentRequirement = 0,
                                NameInformation = fileNameInformation
                            };
                            FileAllInformation parsedAllInformation = FileAllInformation.ReadFrom(allInformation.ToByteArray());
                            TestAssertions.Equal(allInformation.BasicInformation.CreationTime, parsedAllInformation.BasicInformation.CreationTime, "Unexpected FILE_ALL_INFORMATION basic creation time.");
                            TestAssertions.Equal(allInformation.StandardInformation.EndOfFile, parsedAllInformation.StandardInformation.EndOfFile, "Unexpected FILE_ALL_INFORMATION EOF size.");
                            TestAssertions.Equal(allInformation.AccessFlags, parsedAllInformation.AccessFlags, "Unexpected FILE_ALL_INFORMATION access mask.");
                            TestAssertions.Equal(allInformation.NameInformation.FileName, parsedAllInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name payload.");

                            FileInternalInformation internalInformation = new FileInternalInformation
                            {
                                IndexNumber = 0x1122334455667788UL
                            };
                            FileInternalInformation parsedInternalInformation = FileInternalInformation.ReadFrom(internalInformation.ToByteArray());
                            TestAssertions.Equal(internalInformation.IndexNumber, parsedInternalInformation.IndexNumber, "Unexpected FILE_INTERNAL_INFORMATION index number.");

                            FileFsSizeInformation fileSystemSizeInformation = new FileFsSizeInformation
                            {
                                TotalAllocationUnits = 4096,
                                AvailableAllocationUnits = 3072,
                                SectorsPerAllocationUnit = 8,
                                BytesPerSector = 512
                            };
                            FileFsSizeInformation parsedFileSystemSizeInformation = FileFsSizeInformation.ReadFrom(fileSystemSizeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemSizeInformation.TotalAllocationUnits, parsedFileSystemSizeInformation.TotalAllocationUnits, "Unexpected FILE_FS_SIZE_INFORMATION total allocation units.");
                            TestAssertions.Equal(fileSystemSizeInformation.AvailableAllocationUnits, parsedFileSystemSizeInformation.AvailableAllocationUnits, "Unexpected FILE_FS_SIZE_INFORMATION available allocation units.");
                            TestAssertions.Equal(fileSystemSizeInformation.SectorsPerAllocationUnit, parsedFileSystemSizeInformation.SectorsPerAllocationUnit, "Unexpected FILE_FS_SIZE_INFORMATION sectors per allocation unit.");
                            TestAssertions.Equal(fileSystemSizeInformation.BytesPerSector, parsedFileSystemSizeInformation.BytesPerSector, "Unexpected FILE_FS_SIZE_INFORMATION bytes per sector.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsSizeInformation.ReadFrom(new byte[23]),
                                "Expected truncated FILE_FS_SIZE_INFORMATION payloads to be rejected.");

                            FileFsVolumeInformation fileSystemVolumeInformation = new FileFsVolumeInformation
                            {
                                VolumeCreationTime = 123456789UL,
                                VolumeSerialNumber = 0xA1B2C3D4U,
                                SupportsObjects = false,
                                VolumeLabel = "share"
                            };
                            FileFsVolumeInformation parsedFileSystemVolumeInformation = FileFsVolumeInformation.ReadFrom(fileSystemVolumeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemVolumeInformation.VolumeCreationTime, parsedFileSystemVolumeInformation.VolumeCreationTime, "Unexpected FILE_FS_VOLUME_INFORMATION creation time.");
                            TestAssertions.Equal(fileSystemVolumeInformation.VolumeSerialNumber, parsedFileSystemVolumeInformation.VolumeSerialNumber, "Unexpected FILE_FS_VOLUME_INFORMATION serial number.");
                            TestAssertions.Equal(fileSystemVolumeInformation.VolumeLabel, parsedFileSystemVolumeInformation.VolumeLabel, "Unexpected FILE_FS_VOLUME_INFORMATION label.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsVolumeInformation.ReadFrom(new byte[17]),
                                "Expected truncated FILE_FS_VOLUME_INFORMATION payloads to be rejected.");

                            FileFsAttributeInformation fileSystemAttributeInformation = new FileFsAttributeInformation
                            {
                                FileSystemAttributes = FileSystemAttributesFlags.CasePreservedNames | FileSystemAttributesFlags.UnicodeOnDisk | FileSystemAttributesFlags.PersistentAcls,
                                MaximumComponentNameLength = 255,
                                FileSystemName = "NTFS"
                            };
                            FileFsAttributeInformation parsedFileSystemAttributeInformation = FileFsAttributeInformation.ReadFrom(fileSystemAttributeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemAttributeInformation.FileSystemAttributes, parsedFileSystemAttributeInformation.FileSystemAttributes, "Unexpected FILE_FS_ATTRIBUTE_INFORMATION flags.");
                            TestAssertions.Equal(fileSystemAttributeInformation.MaximumComponentNameLength, parsedFileSystemAttributeInformation.MaximumComponentNameLength, "Unexpected FILE_FS_ATTRIBUTE_INFORMATION maximum component length.");
                            TestAssertions.Equal(fileSystemAttributeInformation.FileSystemName, parsedFileSystemAttributeInformation.FileSystemName, "Unexpected FILE_FS_ATTRIBUTE_INFORMATION filesystem name.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsAttributeInformation.ReadFrom(new byte[11]),
                                "Expected truncated FILE_FS_ATTRIBUTE_INFORMATION payloads to be rejected.");

                            FileFsDeviceInformation fileSystemDeviceInformation = new FileFsDeviceInformation
                            {
                                DeviceType = FileSystemDeviceType.Disk,
                                Characteristics = FileSystemDeviceCharacteristics.RemoteDevice | FileSystemDeviceCharacteristics.DeviceIsMounted
                            };
                            FileFsDeviceInformation parsedFileSystemDeviceInformation = FileFsDeviceInformation.ReadFrom(fileSystemDeviceInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemDeviceInformation.DeviceType, parsedFileSystemDeviceInformation.DeviceType, "Unexpected FILE_FS_DEVICE_INFORMATION device type.");
                            TestAssertions.Equal(fileSystemDeviceInformation.Characteristics, parsedFileSystemDeviceInformation.Characteristics, "Unexpected FILE_FS_DEVICE_INFORMATION characteristics.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsDeviceInformation.ReadFrom(new byte[7]),
                                "Expected truncated FILE_FS_DEVICE_INFORMATION payloads to be rejected.");

                            FileFsFullSizeInformation fileSystemFullSizeInformation = new FileFsFullSizeInformation
                            {
                                TotalAllocationUnits = 4096,
                                CallerAvailableAllocationUnits = 2048,
                                ActualAvailableAllocationUnits = 3072,
                                SectorsPerAllocationUnit = 8,
                                BytesPerSector = 512
                            };
                            FileFsFullSizeInformation parsedFileSystemFullSizeInformation = FileFsFullSizeInformation.ReadFrom(fileSystemFullSizeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemFullSizeInformation.TotalAllocationUnits, parsedFileSystemFullSizeInformation.TotalAllocationUnits, "Unexpected FILE_FS_FULL_SIZE_INFORMATION total allocation units.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.CallerAvailableAllocationUnits, parsedFileSystemFullSizeInformation.CallerAvailableAllocationUnits, "Unexpected FILE_FS_FULL_SIZE_INFORMATION caller available allocation units.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.ActualAvailableAllocationUnits, parsedFileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Unexpected FILE_FS_FULL_SIZE_INFORMATION actual available allocation units.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.SectorsPerAllocationUnit, parsedFileSystemFullSizeInformation.SectorsPerAllocationUnit, "Unexpected FILE_FS_FULL_SIZE_INFORMATION sectors per allocation unit.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.BytesPerSector, parsedFileSystemFullSizeInformation.BytesPerSector, "Unexpected FILE_FS_FULL_SIZE_INFORMATION bytes per sector.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsFullSizeInformation.ReadFrom(new byte[31]),
                                "Expected truncated FILE_FS_FULL_SIZE_INFORMATION payloads to be rejected.");

                            FileFsSectorSizeInformation fileSystemSectorSizeInformation = new FileFsSectorSizeInformation
                            {
                                LogicalBytesPerSector = 512,
                                PhysicalBytesPerSectorForAtomicity = 4096,
                                PhysicalBytesPerSectorForPerformance = 4096,
                                FileSystemEffectivePhysicalBytesPerSectorForAtomicity = 512,
                                Flags = FileSystemSectorSizeFlags.AlignedDevice | FileSystemSectorSizeFlags.PartitionAlignedOnDevice,
                                ByteOffsetForSectorAlignment = 0,
                                ByteOffsetForPartitionAlignment = 0
                            };
                            FileFsSectorSizeInformation parsedFileSystemSectorSizeInformation = FileFsSectorSizeInformation.ReadFrom(fileSystemSectorSizeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemSectorSizeInformation.LogicalBytesPerSector, parsedFileSystemSectorSizeInformation.LogicalBytesPerSector, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION logical bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.PhysicalBytesPerSectorForAtomicity, parsedFileSystemSectorSizeInformation.PhysicalBytesPerSectorForAtomicity, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION atomicity bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.PhysicalBytesPerSectorForPerformance, parsedFileSystemSectorSizeInformation.PhysicalBytesPerSectorForPerformance, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION performance bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.FileSystemEffectivePhysicalBytesPerSectorForAtomicity, parsedFileSystemSectorSizeInformation.FileSystemEffectivePhysicalBytesPerSectorForAtomicity, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION effective bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.Flags, parsedFileSystemSectorSizeInformation.Flags, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION flags.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsSectorSizeInformation.ReadFrom(new byte[27]),
                                "Expected truncated FILE_FS_SECTOR_SIZE_INFORMATION payloads to be rejected.");

                            FileAllocationInformation allocationInformation = FileAllocationInformation.ReadFrom(new FileAllocationInformation
                            {
                                AllocationSize = 16384
                            }.ToByteArray());
                            TestAssertions.Equal(16384UL, allocationInformation.AllocationSize, "Unexpected FILE_ALLOCATION_INFORMATION allocation size.");

                            FileEndOfFileInformation endOfFileInformation = FileEndOfFileInformation.ReadFrom(new FileEndOfFileInformation
                            {
                                EndOfFile = 777
                            }.ToByteArray());
                            TestAssertions.Equal(777UL, endOfFileInformation.EndOfFile, "Unexpected FILE_END_OF_FILE_INFORMATION EOF size.");

                            FileDispositionInformation dispositionInformation = FileDispositionInformation.ReadFrom(new FileDispositionInformation
                            {
                                DeletePending = true
                            }.ToByteArray());
                            TestAssertions.True(dispositionInformation.DeletePending, "Expected FILE_DISPOSITION_INFORMATION delete-pending to round-trip.");

                            FileRenameInformationType2 renameInformation = new FileRenameInformationType2
                            {
                                ReplaceIfExists = true,
                                RootDirectory = 0,
                                FileName = "archive\\notes-renamed.txt"
                            };
                            FileRenameInformationType2 parsedRenameInformation = FileRenameInformationType2.ReadFrom(renameInformation.ToByteArray());
                            TestAssertions.True(parsedRenameInformation.ReplaceIfExists, "Expected FILE_RENAME_INFORMATION_TYPE_2 ReplaceIfExists to round-trip.");
                            TestAssertions.Equal(renameInformation.FileName, parsedRenameInformation.FileName, "Unexpected FILE_RENAME_INFORMATION_TYPE_2 path.");

                            byte[] directoryInformationBytes = FileDirectoryInformationEntry.EncodeEntries(new FileDirectoryInformationEntry[]
                            {
                                new FileDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 1,
                                    LastAccessTime = 2,
                                    LastWriteTime = 3,
                                    ChangeTime = 4,
                                    EndOfFile = 5,
                                    AllocationSize = 8,
                                    FileAttributes = ProtocolFileAttributes.Archive,
                                    FileName = "alpha.txt"
                                },
                                new FileDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 10,
                                    LastAccessTime = 11,
                                    LastWriteTime = 12,
                                    ChangeTime = 13,
                                    EndOfFile = 0,
                                    AllocationSize = 0,
                                    FileAttributes = ProtocolFileAttributes.Directory,
                                    FileName = "folder"
                                }
                            });
                            FileDirectoryInformationEntry[] parsedDirectoryEntries = FileDirectoryInformationEntry.DecodeEntries(directoryInformationBytes);
                            TestAssertions.Equal(2, parsedDirectoryEntries.Length, "Expected FILE_DIRECTORY_INFORMATION to round-trip both entries.");
                            TestAssertions.Equal("alpha.txt", parsedDirectoryEntries[0].FileName, "Unexpected first FILE_DIRECTORY_INFORMATION entry name.");
                            TestAssertions.Equal(ProtocolFileAttributes.Directory, parsedDirectoryEntries[1].FileAttributes, "Unexpected second FILE_DIRECTORY_INFORMATION entry attributes.");

                            byte[] fullDirectoryInformationBytes = FileFullDirectoryInformationEntry.EncodeEntries(new FileFullDirectoryInformationEntry[]
                            {
                                new FileFullDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 21,
                                    LastAccessTime = 22,
                                    LastWriteTime = 23,
                                    ChangeTime = 24,
                                    EndOfFile = 25,
                                    AllocationSize = 32,
                                    FileAttributes = ProtocolFileAttributes.Normal,
                                    EaSize = 0,
                                    FileName = "beta.log"
                                }
                            });
                            FileFullDirectoryInformationEntry[] parsedFullDirectoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(fullDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedFullDirectoryEntries.Length, "Expected FILE_FULL_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("beta.log", parsedFullDirectoryEntries[0].FileName, "Unexpected FILE_FULL_DIR_INFORMATION entry name.");
                            TestAssertions.Equal(32UL, parsedFullDirectoryEntries[0].AllocationSize, "Unexpected FILE_FULL_DIR_INFORMATION allocation size.");

                            byte[] bothDirectoryInformationBytes = FileBothDirectoryInformationEntry.EncodeEntries(new FileBothDirectoryInformationEntry[]
                            {
                                new FileBothDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 26,
                                    LastAccessTime = 27,
                                    LastWriteTime = 28,
                                    ChangeTime = 29,
                                    EndOfFile = 30,
                                    AllocationSize = 32,
                                    FileAttributes = ProtocolFileAttributes.Archive,
                                    EaSize = 0,
                                    ShortName = "BETA~1",
                                    FileName = "beta.log"
                                }
                            });
                            FileBothDirectoryInformationEntry[] parsedBothDirectoryEntries = FileBothDirectoryInformationEntry.DecodeEntries(bothDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedBothDirectoryEntries.Length, "Expected FILE_BOTH_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("BETA~1", parsedBothDirectoryEntries[0].ShortName, "Unexpected FILE_BOTH_DIR_INFORMATION short name.");
                            TestAssertions.Equal("beta.log", parsedBothDirectoryEntries[0].FileName, "Unexpected FILE_BOTH_DIR_INFORMATION entry name.");

                            byte[] idBothDirectoryInformationBytes = FileIdBothDirectoryInformationEntry.EncodeEntries(new FileIdBothDirectoryInformationEntry[]
                            {
                                new FileIdBothDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 31,
                                    LastAccessTime = 32,
                                    LastWriteTime = 33,
                                    ChangeTime = 34,
                                    EndOfFile = 35,
                                    AllocationSize = 40,
                                    FileAttributes = ProtocolFileAttributes.Archive,
                                    EaSize = 0,
                                    ShortName = "BETA~1",
                                    FileId = 44,
                                    FileName = "beta.log"
                                }
                            });
                            FileIdBothDirectoryInformationEntry[] parsedIdBothDirectoryEntries = FileIdBothDirectoryInformationEntry.DecodeEntries(idBothDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedIdBothDirectoryEntries.Length, "Expected FILE_ID_BOTH_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("BETA~1", parsedIdBothDirectoryEntries[0].ShortName, "Unexpected FILE_ID_BOTH_DIR_INFORMATION short name.");
                            TestAssertions.Equal(44UL, parsedIdBothDirectoryEntries[0].FileId, "Unexpected FILE_ID_BOTH_DIR_INFORMATION file identifier.");

                            byte[] idFullDirectoryInformationBytes = FileIdFullDirectoryInformationEntry.EncodeEntries(new FileIdFullDirectoryInformationEntry[]
                            {
                                new FileIdFullDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 41,
                                    LastAccessTime = 42,
                                    LastWriteTime = 43,
                                    ChangeTime = 44,
                                    EndOfFile = 45,
                                    AllocationSize = 48,
                                    FileAttributes = ProtocolFileAttributes.Normal,
                                    EaSize = 0,
                                    Reserved = 0,
                                    FileId = 54,
                                    FileName = "gamma.bin"
                                }
                            });
                            FileIdFullDirectoryInformationEntry[] parsedIdFullDirectoryEntries = FileIdFullDirectoryInformationEntry.DecodeEntries(idFullDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedIdFullDirectoryEntries.Length, "Expected FILE_ID_FULL_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("gamma.bin", parsedIdFullDirectoryEntries[0].FileName, "Unexpected FILE_ID_FULL_DIR_INFORMATION entry name.");
                            TestAssertions.Equal(54UL, parsedIdFullDirectoryEntries[0].FileId, "Unexpected FILE_ID_FULL_DIR_INFORMATION file identifier.");

                            Smb2QueryInfoRequest queryInfoRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.NetworkOpenInformation,
                                OutputBufferLength = 512,
                                AdditionalInformation = 0,
                                Flags = 0,
                                PersistentFileId = 9,
                                VolatileFileId = 10,
                                InputBuffer = Array.Empty<byte>()
                            };
                            byte[] queryInfoRequestBytes = queryInfoRequest.ToByteArray();
                            Smb2QueryInfoRequest parsedQueryInfoRequest = Smb2QueryInfoRequest.ReadFrom(queryInfoRequestBytes);
                            Smb2QueryInfoRequestValidator.Validate(parsedQueryInfoRequest);
                            TestAssertions.Equal(FileInformationClass.NetworkOpenInformation, parsedQueryInfoRequest.FileInfoClass, "Unexpected query-info information class.");
                            TestAssertions.Equal(512U, parsedQueryInfoRequest.OutputBufferLength, "Unexpected query-info output-buffer length.");

                            Smb2QueryInfoRequest allInfoRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.AllInformation,
                                OutputBufferLength = 512,
                                PersistentFileId = 11,
                                VolatileFileId = 12,
                                InputBuffer = Array.Empty<byte>()
                            };
                            Smb2QueryInfoRequest parsedAllInfoRequest = Smb2QueryInfoRequest.ReadFrom(allInfoRequest.ToByteArray());
                            Smb2QueryInfoRequestValidator.Validate(parsedAllInfoRequest);
                            TestAssertions.Equal(FileInformationClass.AllInformation, parsedAllInfoRequest.FileInfoClass, "Unexpected FILE_ALL_INFORMATION query-info class.");

                            Smb2QueryInfoRequest internalInfoRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.InternalInformation,
                                OutputBufferLength = 8,
                                PersistentFileId = 21,
                                VolatileFileId = 22,
                                InputBuffer = Array.Empty<byte>()
                            };
                            Smb2QueryInfoRequest parsedInternalInfoRequest = Smb2QueryInfoRequest.ReadFrom(internalInfoRequest.ToByteArray());
                            Smb2QueryInfoRequestValidator.Validate(parsedInternalInfoRequest);
                            TestAssertions.Equal(FileInformationClass.InternalInformation, parsedInternalInfoRequest.FileInfoClass, "Unexpected FILE_INTERNAL_INFORMATION query-info class.");

                            Smb2QueryInfoRequest fileSystemSizeRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.FileSystem,
                                FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SizeInformation,
                                OutputBufferLength = 512,
                                PersistentFileId = 13,
                                VolatileFileId = 14,
                                InputBuffer = Array.Empty<byte>()
                            };
                            Smb2QueryInfoRequest parsedFileSystemSizeRequest = Smb2QueryInfoRequest.ReadFrom(fileSystemSizeRequest.ToByteArray());
                            Smb2QueryInfoRequestValidator.Validate(parsedFileSystemSizeRequest);
                            TestAssertions.Equal(Smb2InfoType.FileSystem, parsedFileSystemSizeRequest.InfoType, "Unexpected filesystem query-info type.");
                            TestAssertions.Equal((byte)FileSystemInformationClass.SizeInformation, (byte)parsedFileSystemSizeRequest.FileInfoClass, "Unexpected FILE_FS_SIZE_INFORMATION query-info class.");

                            Smb2QueryInfoResponse queryInfoResponse = new Smb2QueryInfoResponse
                            {
                                OutputBuffer = networkOpenInformation.ToByteArray()
                            };
                            byte[] queryInfoResponseBytes = queryInfoResponse.ToByteArray();
                            Smb2QueryInfoResponse parsedQueryInfoResponse = Smb2QueryInfoResponse.ReadFrom(queryInfoResponseBytes);
                            Smb2QueryInfoResponseValidator.Validate(parsedQueryInfoResponse);
                            TestAssertions.SequenceEqual(queryInfoResponse.OutputBuffer, parsedQueryInfoResponse.OutputBuffer, "Unexpected query-info response payload.");

                            Smb2QueryDirectoryRequest queryDirectoryRequest = new Smb2QueryDirectoryRequest
                            {
                                FileInfoClass = FileInformationClass.DirectoryInformation,
                                Flags = Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                FileIndex = 0,
                                PersistentFileId = 11,
                                VolatileFileId = 12,
                                OutputBufferLength = 1024,
                                FileNamePattern = "*.txt"
                            };
                            byte[] queryDirectoryRequestBytes = queryDirectoryRequest.ToByteArray();
                            Smb2QueryDirectoryRequest parsedQueryDirectoryRequest = Smb2QueryDirectoryRequest.ReadFrom(queryDirectoryRequestBytes);
                            Smb2QueryDirectoryRequestValidator.Validate(parsedQueryDirectoryRequest);
                            TestAssertions.Equal(FileInformationClass.DirectoryInformation, parsedQueryDirectoryRequest.FileInfoClass, "Unexpected query-directory information class.");
                            TestAssertions.Equal("*.txt", parsedQueryDirectoryRequest.FileNamePattern, "Unexpected query-directory search pattern.");
                            TestAssertions.Equal(
                                Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                parsedQueryDirectoryRequest.Flags,
                                "Unexpected query-directory flags.");

                            Smb2QueryDirectoryResponse queryDirectoryResponse = new Smb2QueryDirectoryResponse
                            {
                                OutputBuffer = directoryInformationBytes
                            };
                            byte[] queryDirectoryResponseBytes = queryDirectoryResponse.ToByteArray();
                            Smb2QueryDirectoryResponse parsedQueryDirectoryResponse = Smb2QueryDirectoryResponse.ReadFrom(queryDirectoryResponseBytes);
                            Smb2QueryDirectoryResponseValidator.Validate(parsedQueryDirectoryResponse);
                            TestAssertions.SequenceEqual(queryDirectoryResponse.OutputBuffer, parsedQueryDirectoryResponse.OutputBuffer, "Unexpected query-directory response payload.");

                            Smb2SetInfoRequest setInfoRequest = new Smb2SetInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.RenameInformation,
                                AdditionalInformation = 0,
                                PersistentFileId = 9,
                                VolatileFileId = 10,
                                Buffer = renameInformation.ToByteArray()
                            };
                            byte[] setInfoRequestBytes = setInfoRequest.ToByteArray();
                            Smb2SetInfoRequest parsedSetInfoRequest = Smb2SetInfoRequest.ReadFrom(setInfoRequestBytes);
                            Smb2SetInfoRequestValidator.Validate(parsedSetInfoRequest);
                            TestAssertions.Equal(FileInformationClass.RenameInformation, parsedSetInfoRequest.FileInfoClass, "Unexpected set-info information class.");
                            TestAssertions.SequenceEqual(setInfoRequest.Buffer, parsedSetInfoRequest.Buffer, "Unexpected set-info request buffer.");

                            Smb2SetInfoResponse setInfoResponse = Smb2SetInfoResponse.ReadFrom(new Smb2SetInfoResponse().ToByteArray());
                            Smb2SetInfoResponseValidator.Validate(setInfoResponse);

                            byte[] paddedQueryRequest = new byte[queryInfoRequestBytes.Length + 8];
                            queryInfoRequestBytes.CopyTo(paddedQueryRequest, 0);
                            byte[] trimmedQueryRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.QueryInfo, paddedQueryRequest);
                            TestAssertions.SequenceEqual(queryInfoRequestBytes, trimmedQueryRequest, "Unexpected trimmed compounded query-info request payload.");

                            byte[] paddedQueryResponse = new byte[queryInfoResponseBytes.Length + 8];
                            queryInfoResponseBytes.CopyTo(paddedQueryResponse, 0);
                            byte[] trimmedQueryResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.QueryInfo, paddedQueryResponse);
                            TestAssertions.SequenceEqual(queryInfoResponseBytes, trimmedQueryResponse, "Unexpected trimmed compounded query-info response payload.");

                            byte[] paddedSetRequest = new byte[setInfoRequestBytes.Length + 8];
                            setInfoRequestBytes.CopyTo(paddedSetRequest, 0);
                            byte[] trimmedSetRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.SetInfo, paddedSetRequest);
                            TestAssertions.SequenceEqual(setInfoRequestBytes, trimmedSetRequest, "Unexpected trimmed compounded set-info request payload.");

                            byte[] paddedQueryDirectoryRequest = new byte[queryDirectoryRequestBytes.Length + 8];
                            queryDirectoryRequestBytes.CopyTo(paddedQueryDirectoryRequest, 0);
                            byte[] trimmedQueryDirectoryRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.QueryDirectory, paddedQueryDirectoryRequest);
                            TestAssertions.SequenceEqual(queryDirectoryRequestBytes, trimmedQueryDirectoryRequest, "Unexpected trimmed compounded query-directory request payload.");

                            byte[] paddedQueryDirectoryResponse = new byte[queryDirectoryResponseBytes.Length + 8];
                            queryDirectoryResponseBytes.CopyTo(paddedQueryDirectoryResponse, 0);
                            byte[] trimmedQueryDirectoryResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.QueryDirectory, paddedQueryDirectoryResponse);
                            TestAssertions.SequenceEqual(queryDirectoryResponseBytes, trimmedQueryDirectoryResponse, "Unexpected trimmed compounded query-directory response payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Metadata",
                        caseId: "MetadataValidatorsRejectUnsupportedInputs",
                        displayName: "SMB2 metadata validators reject unsupported info types, malformed FSCC payloads, and non-zero compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryInfoRequestValidator.Validate(new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.Security,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "Security query-info requests should remain unsupported for the current metadata slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryInfoRequestValidator.Validate(new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.NameInformation,
                                    OutputBufferLength = 64,
                                    Flags = 1,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "Query-info flags should remain unsupported for the current metadata slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryInfoRequestValidator.Validate(new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.FileSystem,
                                    FileInfoClass = unchecked((FileInformationClass)0x7F),
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "Filesystem query-info requests should reject unknown information classes.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryDirectoryRequestValidator.Validate(new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    Flags = Smb2QueryDirectoryFlags.IndexSpecified,
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    FileNamePattern = "*"
                                }),
                                "Index-specified query-directory requests should remain unsupported for the current enumeration slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryDirectoryRequestValidator.Validate(new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    OutputBufferLength = 0,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    FileNamePattern = "*"
                                }),
                                "Query-directory requests should require a non-zero output buffer.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryDirectoryRequestValidator.Validate(new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    FileNamePattern = "folder\\*.txt"
                                }),
                                "Query-directory search patterns should reject path separators.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2SetInfoRequestValidator.Validate(new Smb2SetInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.EndOfFileInformation,
                                    AdditionalInformation = 1,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Buffer = new byte[] { 0x01 }
                                }),
                                "Set-info additional-information flags should remain unsupported for the current metadata slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2SetInfoRequestValidator.Validate(new Smb2SetInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    PersistentFileId = 0,
                                    VolatileFileId = 0,
                                    Buffer = new byte[] { 0x01 }
                                }),
                                "Set-info requests should require a file identifier pair.");

                            byte[] invalidStandardInformation = new FileStandardInformation
                            {
                                AllocationSize = 1,
                                EndOfFile = 1,
                                NumberOfLinks = 1,
                                DeletePending = false,
                                Directory = false
                            }.ToByteArray();
                            invalidStandardInformation[20] = 2;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileStandardInformation.ReadFrom(invalidStandardInformation),
                                "FILE_STANDARD_INFORMATION should reject invalid Boolean fields.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileNameInformation.ReadFrom(new byte[] { 0x03, 0x00, 0x00, 0x00, 0x41, 0x00, 0x42 }),
                                "FILE_NAME_INFORMATION should reject odd UTF-16 lengths.");

                            byte[] invalidDirectoryInformation = FileDirectoryInformationEntry.EncodeEntries(new FileDirectoryInformationEntry[]
                            {
                                new FileDirectoryInformationEntry
                                {
                                    FileName = "odd.txt"
                                }
                            });
                            invalidDirectoryInformation[60] = 0x03;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileDirectoryInformationEntry.DecodeEntries(invalidDirectoryInformation),
                                "FILE_DIRECTORY_INFORMATION should reject odd UTF-16 file-name lengths.");

                            byte[] invalidBothDirectoryInformation = FileBothDirectoryInformationEntry.EncodeEntries(new FileBothDirectoryInformationEntry[]
                            {
                                new FileBothDirectoryInformationEntry
                                {
                                    FileName = "odd.txt"
                                }
                            });
                            invalidBothDirectoryInformation[60] = 0x03;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileBothDirectoryInformationEntry.DecodeEntries(invalidBothDirectoryInformation),
                                "FILE_BOTH_DIR_INFORMATION should reject odd UTF-16 file-name lengths.");

                            byte[] invalidRenameInformation = new FileRenameInformationType2
                            {
                                ReplaceIfExists = false,
                                RootDirectory = 0,
                                FileName = "renamed.txt"
                            }.ToByteArray();
                            invalidRenameInformation[0] = 2;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileRenameInformationType2.ReadFrom(invalidRenameInformation),
                                "FILE_RENAME_INFORMATION_TYPE_2 should reject invalid ReplaceIfExists values.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileDispositionInformation.ReadFrom(new byte[] { 0x02 }),
                                "FILE_DISPOSITION_INFORMATION should reject invalid delete-pending values.");

                            byte[] paddedSetResponse = new byte[3];
                            new Smb2SetInfoResponse().ToByteArray().CopyTo(paddedSetResponse, 0);
                            paddedSetResponse[2] = 0x7F;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.SetInfo, paddedSetResponse),
                                "Compounded set-info responses should reject non-zero trailing padding.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
