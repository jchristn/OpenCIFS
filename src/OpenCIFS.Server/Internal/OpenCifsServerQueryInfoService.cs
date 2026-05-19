namespace OpenCIFS.Server
{
    using System;
    using System.IO;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerQueryInfoService
    {
        private const uint FileSystemBytesPerSector = 512;
        private const uint FileSystemSectorsPerAllocationUnit = 8;
        private const int FileSystemMaximumComponentNameLength = 255;
        private const string DefaultFileSystemName = "NTFS";

        private readonly OpenCifsServerFileStateTracker _FileStateTracker;

        public OpenCifsServerQueryInfoService(OpenCifsServerFileStateTracker fileStateTracker)
        {
            _FileStateTracker = fileStateTracker ?? throw new ArgumentNullException(nameof(fileStateTracker), "FileStateTracker cannot be null.");
        }

        public static string FormatQueryInfoClass(Smb2QueryInfoRequest request)
        {
            if (request.InfoType == Smb2InfoType.FileSystem)
            {
                return ((FileSystemInformationClass)(byte)request.FileInfoClass).ToString();
            }

            return request.FileInfoClass.ToString();
        }

        public NtStatus TryBuildOutputBuffer(ServerOpenRecord openRecord, Smb2QueryInfoRequest request, out byte[] outputBuffer)
        {
            outputBuffer = Array.Empty<byte>();

            if (request.InputBuffer.Length != 0 || request.AdditionalInformation != 0 || request.Flags != 0)
            {
                return NtStatus.InvalidParameter;
            }

            switch (request.InfoType)
            {
                case Smb2InfoType.File:
                    return TryBuildFileInfoOutputBuffer(openRecord, request.FileInfoClass, out outputBuffer);
                case Smb2InfoType.FileSystem:
                    return TryBuildFileSystemInfoOutputBuffer(openRecord, (FileSystemInformationClass)(byte)request.FileInfoClass, out outputBuffer);
                default:
                    return NtStatus.NotSupported;
            }
        }

        private NtStatus TryBuildFileInfoOutputBuffer(ServerOpenRecord openRecord, FileInformationClass informationClass, out byte[] outputBuffer)
        {
            outputBuffer = Array.Empty<byte>();

            switch (informationClass)
            {
                case FileInformationClass.BasicInformation:
                    if (!OpenCifsServerFilePolicy.CanReadAttributes(openRecord.DesiredAccess))
                    {
                        return NtStatus.AccessDenied;
                    }

                    outputBuffer = BuildBasicInformationOutput(openRecord);
                    return NtStatus.Success;
                case FileInformationClass.StandardInformation:
                    outputBuffer = BuildStandardInformationOutput(openRecord);
                    return NtStatus.Success;
                case FileInformationClass.InternalInformation:
                    outputBuffer = new FileInternalInformation
                    {
                        IndexNumber = openRecord.State.PersistentFileId
                    }.ToByteArray();
                    return NtStatus.Success;
                case FileInformationClass.NameInformation:
                    outputBuffer = new FileNameInformation
                    {
                        FileName = openRecord.State.Path
                    }.ToByteArray();
                    return NtStatus.Success;
                case FileInformationClass.NetworkOpenInformation:
                    if (!OpenCifsServerFilePolicy.CanReadAttributes(openRecord.DesiredAccess))
                    {
                        return NtStatus.AccessDenied;
                    }

                    outputBuffer = BuildNetworkOpenInformationOutput(openRecord);
                    return NtStatus.Success;
                case FileInformationClass.AllInformation:
                    if (!OpenCifsServerFilePolicy.CanReadAttributes(openRecord.DesiredAccess))
                    {
                        return NtStatus.AccessDenied;
                    }

                    outputBuffer = BuildAllInformationOutput(openRecord);
                    return NtStatus.Success;
                default:
                    return NtStatus.NotSupported;
            }
        }

        private NtStatus TryBuildFileSystemInfoOutputBuffer(ServerOpenRecord openRecord, FileSystemInformationClass informationClass, out byte[] outputBuffer)
        {
            outputBuffer = Array.Empty<byte>();

            switch (informationClass)
            {
                case FileSystemInformationClass.VolumeInformation:
                    outputBuffer = BuildFileSystemVolumeInformation(openRecord.ShareRootPath, openRecord.ShareName).ToByteArray();
                    return NtStatus.Success;
                case FileSystemInformationClass.SizeInformation:
                    outputBuffer = BuildFileSystemSizeInformation(openRecord.ShareRootPath).ToByteArray();
                    return NtStatus.Success;
                case FileSystemInformationClass.DeviceInformation:
                    outputBuffer = BuildFileSystemDeviceInformation().ToByteArray();
                    return NtStatus.Success;
                case FileSystemInformationClass.AttributeInformation:
                    outputBuffer = BuildFileSystemAttributeInformation(openRecord.Backend, openRecord.ShareRootPath).ToByteArray();
                    return NtStatus.Success;
                case FileSystemInformationClass.FullSizeInformation:
                    outputBuffer = BuildFileSystemFullSizeInformation(openRecord.ShareRootPath).ToByteArray();
                    return NtStatus.Success;
                case FileSystemInformationClass.SectorSizeInformation:
                    outputBuffer = BuildFileSystemSectorSizeInformation().ToByteArray();
                    return NtStatus.Success;
                default:
                    return NtStatus.NotSupported;
            }
        }

        private byte[] BuildBasicInformationOutput(ServerOpenRecord openRecord)
        {
            FileMetadata metadata = _FileStateTracker.BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
            return new FileBasicInformation
            {
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                FileAttributes = metadata.FileAttributes
            }.ToByteArray();
        }

        private byte[] BuildStandardInformationOutput(ServerOpenRecord openRecord)
        {
            FileMetadata metadata = _FileStateTracker.BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
            return new FileStandardInformation
            {
                AllocationSize = metadata.AllocationSize,
                EndOfFile = metadata.EndOfFile,
                NumberOfLinks = 1,
                DeletePending = openRecord.State.IsDeletePending,
                Directory = openRecord.IsDirectory
            }.ToByteArray();
        }

        private byte[] BuildNetworkOpenInformationOutput(ServerOpenRecord openRecord)
        {
            FileMetadata metadata = _FileStateTracker.BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
            return new FileNetworkOpenInformation
            {
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                AllocationSize = metadata.AllocationSize,
                EndOfFile = metadata.EndOfFile,
                FileAttributes = metadata.FileAttributes
            }.ToByteArray();
        }

        private byte[] BuildAllInformationOutput(ServerOpenRecord openRecord)
        {
            FileMetadata metadata = _FileStateTracker.BuildFileMetadata(openRecord.Backend, openRecord.FullPath);
            return new FileAllInformation
            {
                BasicInformation = new FileBasicInformation
                {
                    CreationTime = metadata.CreationTime,
                    LastAccessTime = metadata.LastAccessTime,
                    LastWriteTime = metadata.LastWriteTime,
                    ChangeTime = metadata.ChangeTime,
                    FileAttributes = metadata.FileAttributes
                },
                StandardInformation = new FileStandardInformation
                {
                    AllocationSize = metadata.AllocationSize,
                    EndOfFile = metadata.EndOfFile,
                    NumberOfLinks = 1,
                    DeletePending = openRecord.State.IsDeletePending,
                    Directory = openRecord.IsDirectory
                },
                InternalIndexNumber = openRecord.State.PersistentFileId,
                EaSize = 0,
                AccessFlags = openRecord.DesiredAccess,
                CurrentByteOffset = 0,
                Mode = 0,
                AlignmentRequirement = 0,
                NameInformation = new FileNameInformation
                {
                    FileName = openRecord.State.Path
                }
            }.ToByteArray();
        }

        private static FileFsSizeInformation BuildFileSystemSizeInformation(string shareRootPath)
        {
            VolumeCapacitySnapshot snapshot = GetVolumeCapacitySnapshot(shareRootPath);

            return new FileFsSizeInformation
            {
                TotalAllocationUnits = snapshot.TotalAllocationUnits,
                AvailableAllocationUnits = snapshot.AvailableAllocationUnits,
                SectorsPerAllocationUnit = FileSystemSectorsPerAllocationUnit,
                BytesPerSector = FileSystemBytesPerSector
            };
        }

        private static FileFsVolumeInformation BuildFileSystemVolumeInformation(string shareRootPath, string shareName)
        {
            DriveInfo? drive = TryGetDriveInfo(shareRootPath);
            string volumeLabel = string.Empty;

            if (drive != null)
            {
                try
                {
                    if (drive.IsReady)
                    {
                        volumeLabel = drive.VolumeLabel;
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            if (string.IsNullOrWhiteSpace(volumeLabel))
            {
                volumeLabel = shareName;
            }

            string volumeRoot = GetVolumeRoot(shareRootPath);
            DateTime creationTimeUtc;

            try
            {
                creationTimeUtc = Directory.GetCreationTimeUtc(volumeRoot);
            }
            catch (IOException)
            {
                creationTimeUtc = DateTime.UnixEpoch;
            }
            catch (UnauthorizedAccessException)
            {
                creationTimeUtc = DateTime.UnixEpoch;
            }

            if (creationTimeUtc.Kind != DateTimeKind.Utc)
            {
                creationTimeUtc = creationTimeUtc.ToUniversalTime();
            }

            if (creationTimeUtc < DateTime.FromFileTimeUtc(0))
            {
                creationTimeUtc = DateTime.FromFileTimeUtc(0);
            }

            return new FileFsVolumeInformation
            {
                VolumeCreationTime = unchecked((ulong)creationTimeUtc.ToFileTimeUtc()),
                VolumeSerialNumber = ComputeOpaqueVolumeSerialNumber(volumeRoot),
                SupportsObjects = false,
                VolumeLabel = volumeLabel
            };
        }

        private static FileFsDeviceInformation BuildFileSystemDeviceInformation()
        {
            return new FileFsDeviceInformation
            {
                DeviceType = FileSystemDeviceType.Disk,
                Characteristics = FileSystemDeviceCharacteristics.RemoteDevice | FileSystemDeviceCharacteristics.DeviceIsMounted
            };
        }

        private static FileFsAttributeInformation BuildFileSystemAttributeInformation(OpenCifsServerShareBackend backend, string shareRootPath)
        {
            FileSystemAttributesFlags attributes =
                FileSystemAttributesFlags.CasePreservedNames |
                FileSystemAttributesFlags.UnicodeOnDisk |
                FileSystemAttributesFlags.PersistentAcls |
                FileSystemAttributesFlags.SupportsHardLinks |
                FileSystemAttributesFlags.SupportsExtendedAttributes |
                FileSystemAttributesFlags.SupportsOpenByFileId;

            if (backend.Capabilities.SupportsNamedStreams)
            {
                attributes |= FileSystemAttributesFlags.NamedStreams;
            }

            DriveInfo? drive = TryGetDriveInfo(shareRootPath);
            string fileSystemName = DefaultFileSystemName;

            if (drive != null)
            {
                try
                {
                    if (drive.IsReady && !string.IsNullOrWhiteSpace(drive.DriveFormat))
                    {
                        fileSystemName = drive.DriveFormat;
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            return new FileFsAttributeInformation
            {
                FileSystemAttributes = attributes,
                MaximumComponentNameLength = FileSystemMaximumComponentNameLength,
                FileSystemName = fileSystemName
            };
        }

        private static FileFsFullSizeInformation BuildFileSystemFullSizeInformation(string shareRootPath)
        {
            VolumeCapacitySnapshot snapshot = GetVolumeCapacitySnapshot(shareRootPath);
            return new FileFsFullSizeInformation
            {
                TotalAllocationUnits = snapshot.TotalAllocationUnits,
                CallerAvailableAllocationUnits = snapshot.AvailableAllocationUnits,
                ActualAvailableAllocationUnits = snapshot.AvailableAllocationUnits,
                SectorsPerAllocationUnit = FileSystemSectorsPerAllocationUnit,
                BytesPerSector = FileSystemBytesPerSector
            };
        }

        private static FileFsSectorSizeInformation BuildFileSystemSectorSizeInformation()
        {
            return new FileFsSectorSizeInformation
            {
                LogicalBytesPerSector = FileSystemBytesPerSector,
                PhysicalBytesPerSectorForAtomicity = FileSystemBytesPerSector,
                PhysicalBytesPerSectorForPerformance = FileSystemBytesPerSector,
                FileSystemEffectivePhysicalBytesPerSectorForAtomicity = FileSystemBytesPerSector,
                Flags = FileSystemSectorSizeFlags.AlignedDevice | FileSystemSectorSizeFlags.PartitionAlignedOnDevice,
                ByteOffsetForSectorAlignment = 0,
                ByteOffsetForPartitionAlignment = 0
            };
        }

        private static VolumeCapacitySnapshot GetVolumeCapacitySnapshot(string shareRootPath)
        {
            const ulong bytesPerAllocationUnit = FileSystemBytesPerSector * FileSystemSectorsPerAllocationUnit;

            DriveInfo? drive = TryGetDriveInfo(shareRootPath);
            ulong totalAllocationUnits = 0;
            ulong availableAllocationUnits = 0;

            if (drive != null)
            {
                try
                {
                    if (drive.IsReady)
                    {
                        totalAllocationUnits = unchecked((ulong)Math.Max(0L, drive.TotalSize / (long)bytesPerAllocationUnit));
                        availableAllocationUnits = unchecked((ulong)Math.Max(0L, drive.AvailableFreeSpace / (long)bytesPerAllocationUnit));
                    }
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }

            return new VolumeCapacitySnapshot
            {
                TotalAllocationUnits = totalAllocationUnits,
                AvailableAllocationUnits = availableAllocationUnits
            };
        }

        private static DriveInfo? TryGetDriveInfo(string shareRootPath)
        {
            string volumeRoot = GetVolumeRoot(shareRootPath);

            try
            {
                return new DriveInfo(volumeRoot);
            }
            catch (ArgumentException)
            {
                return null;
            }
            catch (IOException)
            {
                return null;
            }
        }

        private static string GetVolumeRoot(string shareRootPath)
        {
            return Path.GetPathRoot(shareRootPath) ?? shareRootPath;
        }

        private static uint ComputeOpaqueVolumeSerialNumber(string volumeRoot)
        {
            string normalizedVolumeRoot = volumeRoot.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar).ToUpperInvariant();
            uint hash = 2166136261;

            for (int index = 0; index < normalizedVolumeRoot.Length; index++)
            {
                hash ^= normalizedVolumeRoot[index];
                hash *= 16777619;
            }

            return hash;
        }
    }
}
