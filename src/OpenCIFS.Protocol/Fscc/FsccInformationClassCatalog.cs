namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Catalog of FSCC information classes needed by the OpenCIFS foundation.
    /// </summary>
    public static class FsccInformationClassCatalog
    {
        /// <summary>
        /// Try to resolve file information class metadata.
        /// </summary>
        /// <param name="informationClass">Information class.</param>
        /// <param name="info">Resolved metadata.</param>
        /// <returns><c>true</c> if metadata was found.</returns>
        public static bool TryGetFileInformationClassInfo(FileInformationClass informationClass, out FsccInformationClassInfo? info)
        {
            return _FileInformationClasses.TryGetValue(informationClass, out info);
        }

        /// <summary>
        /// Try to resolve filesystem information class metadata.
        /// </summary>
        /// <param name="informationClass">Information class.</param>
        /// <param name="info">Resolved metadata.</param>
        /// <returns><c>true</c> if metadata was found.</returns>
        public static bool TryGetFileSystemInformationClassInfo(FileSystemInformationClass informationClass, out FsccInformationClassInfo? info)
        {
            return _FileSystemInformationClasses.TryGetValue(informationClass, out info);
        }

        private static readonly IReadOnlyDictionary<FileInformationClass, FsccInformationClassInfo> _FileInformationClasses =
            new Dictionary<FileInformationClass, FsccInformationClassInfo>
            {
                { FileInformationClass.DirectoryInformation, new FsccInformationClassInfo { Name = "DirectoryInformation", Description = "Directory enumeration records.", RequiresFileHandle = true } },
                { FileInformationClass.FullDirectoryInformation, new FsccInformationClassInfo { Name = "FullDirectoryInformation", Description = "Directory enumeration including EA size.", RequiresFileHandle = true } },
                { FileInformationClass.BasicInformation, new FsccInformationClassInfo { Name = "BasicInformation", Description = "Basic timestamps and attributes.", RequiresFileHandle = true } },
                { FileInformationClass.StandardInformation, new FsccInformationClassInfo { Name = "StandardInformation", Description = "Allocation size, EOF, and link counts.", RequiresFileHandle = true } },
                { FileInformationClass.InternalInformation, new FsccInformationClassInfo { Name = "InternalInformation", Description = "Stable file index number.", RequiresFileHandle = true } },
                { FileInformationClass.NameInformation, new FsccInformationClassInfo { Name = "NameInformation", Description = "Filename information.", RequiresFileHandle = true } },
                { FileInformationClass.RenameInformation, new FsccInformationClassInfo { Name = "RenameInformation", Description = "Rename target information.", RequiresFileHandle = true } },
                { FileInformationClass.DispositionInformation, new FsccInformationClassInfo { Name = "DispositionInformation", Description = "Delete-pending information.", RequiresFileHandle = true } },
                { FileInformationClass.AllocationInformation, new FsccInformationClassInfo { Name = "AllocationInformation", Description = "Allocation size update.", RequiresFileHandle = true } },
                { FileInformationClass.EndOfFileInformation, new FsccInformationClassInfo { Name = "EndOfFileInformation", Description = "End-of-file update.", RequiresFileHandle = true } },
                { FileInformationClass.AllInformation, new FsccInformationClassInfo { Name = "AllInformation", Description = "Compound metadata response.", RequiresFileHandle = true } },
                { FileInformationClass.StreamInformation, new FsccInformationClassInfo { Name = "StreamInformation", Description = "Named stream enumeration.", RequiresFileHandle = true } },
                { FileInformationClass.NetworkOpenInformation, new FsccInformationClassInfo { Name = "NetworkOpenInformation", Description = "Metadata available during create/open.", RequiresFileHandle = true } },
                { FileInformationClass.IdBothDirectoryInformation, new FsccInformationClassInfo { Name = "IdBothDirectoryInformation", Description = "Directory enumeration with file ID and short name.", RequiresFileHandle = true } },
                { FileInformationClass.IdFullDirectoryInformation, new FsccInformationClassInfo { Name = "IdFullDirectoryInformation", Description = "Directory enumeration with file ID.", RequiresFileHandle = true } },
                { FileInformationClass.NormalizedNameInformation, new FsccInformationClassInfo { Name = "NormalizedNameInformation", Description = "Normalized full path information.", RequiresFileHandle = true } }
            };

        private static readonly IReadOnlyDictionary<FileSystemInformationClass, FsccInformationClassInfo> _FileSystemInformationClasses =
            new Dictionary<FileSystemInformationClass, FsccInformationClassInfo>
            {
                { FileSystemInformationClass.VolumeInformation, new FsccInformationClassInfo { Name = "VolumeInformation", Description = "Volume label and serial number.", RequiresFileHandle = false } },
                { FileSystemInformationClass.LabelInformation, new FsccInformationClassInfo { Name = "LabelInformation", Description = "Volume label update.", RequiresFileHandle = false } },
                { FileSystemInformationClass.SizeInformation, new FsccInformationClassInfo { Name = "SizeInformation", Description = "Volume allocation metrics.", RequiresFileHandle = false } },
                { FileSystemInformationClass.DeviceInformation, new FsccInformationClassInfo { Name = "DeviceInformation", Description = "Filesystem device characteristics.", RequiresFileHandle = false } },
                { FileSystemInformationClass.AttributeInformation, new FsccInformationClassInfo { Name = "AttributeInformation", Description = "Filesystem attribute flags.", RequiresFileHandle = false } },
                { FileSystemInformationClass.FullSizeInformation, new FsccInformationClassInfo { Name = "FullSizeInformation", Description = "Detailed free-space metrics.", RequiresFileHandle = false } },
                { FileSystemInformationClass.ObjectIdInformation, new FsccInformationClassInfo { Name = "ObjectIdInformation", Description = "Filesystem object identifier metadata.", RequiresFileHandle = false } },
                { FileSystemInformationClass.SectorSizeInformation, new FsccInformationClassInfo { Name = "SectorSizeInformation", Description = "Physical and logical sector size values.", RequiresFileHandle = false } }
            };
    }
}
