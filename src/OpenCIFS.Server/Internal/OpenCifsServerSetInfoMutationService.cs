namespace OpenCIFS.Server
{
    using System;
    using System.IO;
    using OpenCIFS.Protocol;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using SystemFileAttributes = System.IO.FileAttributes;

    internal sealed class OpenCifsServerSetInfoMutationService
    {
        private readonly Func<OpenCifsServerShareBackend, string, bool> _DeleteBackingObjectIfPresent;
        private readonly OpenCifsServerFileStateTracker _FileStateTracker;
        private readonly OpenCifsServerOpenStateTracker _OpenStateTracker;
        private readonly Action<string, FileNotifyChangeFilter> _PublishModifiedNotification;
        private readonly Action<string, string, bool> _PublishRenameNotification;

        public OpenCifsServerSetInfoMutationService(
            OpenCifsServerFileStateTracker fileStateTracker,
            OpenCifsServerOpenStateTracker openStateTracker,
            Func<OpenCifsServerShareBackend, string, bool> deleteBackingObjectIfPresent,
            Action<string, FileNotifyChangeFilter> publishModifiedNotification,
            Action<string, string, bool> publishRenameNotification)
        {
            _FileStateTracker = fileStateTracker ?? throw new ArgumentNullException(nameof(fileStateTracker), "FileStateTracker cannot be null.");
            _OpenStateTracker = openStateTracker ?? throw new ArgumentNullException(nameof(openStateTracker), "OpenStateTracker cannot be null.");
            _DeleteBackingObjectIfPresent = deleteBackingObjectIfPresent ?? throw new ArgumentNullException(nameof(deleteBackingObjectIfPresent), "DeleteBackingObjectIfPresent cannot be null.");
            _PublishModifiedNotification = publishModifiedNotification ?? throw new ArgumentNullException(nameof(publishModifiedNotification), "PublishModifiedNotification cannot be null.");
            _PublishRenameNotification = publishRenameNotification ?? throw new ArgumentNullException(nameof(publishRenameNotification), "PublishRenameNotification cannot be null.");
        }

        public NtStatus ApplyFileBasicInformation(ServerOpenRecord openRecord, FileBasicInformation information)
        {
            FileNotifyChangeFilter changeNotifyFilter = FileNotifyChangeFilter.None;
            bool explicitChangeTimeApplied = false;
            bool mutatedCreationTime = false;
            bool mutatedAccessTime = false;
            bool mutatedWriteTime = false;
            bool mutatedAttributes = false;

            if (information.ChangeTime != 0)
            {
                if (OpenCifsServerFilePolicy.IsEnableStickyFileTimeDirective(information.ChangeTime))
                {
                    openRecord.SuppressChangeTimeUpdates = false;
                }
                else
                {
                    openRecord.SuppressChangeTimeUpdates = true;

                    if (OpenCifsServerFilePolicy.ShouldApplyExplicitFileTime(information.ChangeTime))
                    {
                        if (!_FileStateTracker.TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.Change, information.ChangeTime))
                        {
                            return NtStatus.InvalidParameter;
                        }

                        explicitChangeTimeApplied = true;
                    }
                }
            }

            if (OpenCifsServerFilePolicy.ShouldApplyExplicitFileTime(information.CreationTime))
            {
                if (!_FileStateTracker.TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.Creation, information.CreationTime))
                {
                    return NtStatus.InvalidParameter;
                }

                mutatedCreationTime = true;
            }

            if (information.LastAccessTime != 0)
            {
                if (OpenCifsServerFilePolicy.IsEnableStickyFileTimeDirective(information.LastAccessTime))
                {
                    openRecord.SuppressAccessTimeUpdates = false;
                }
                else
                {
                    openRecord.SuppressAccessTimeUpdates = true;

                    if (OpenCifsServerFilePolicy.ShouldApplyExplicitFileTime(information.LastAccessTime))
                    {
                        if (!_FileStateTracker.TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.LastAccess, information.LastAccessTime))
                        {
                            return NtStatus.InvalidParameter;
                        }

                        mutatedAccessTime = true;
                    }
                }
            }

            if (information.LastWriteTime != 0)
            {
                if (OpenCifsServerFilePolicy.IsEnableStickyFileTimeDirective(information.LastWriteTime))
                {
                    openRecord.SuppressModificationTimeUpdates = false;
                }
                else
                {
                    openRecord.SuppressModificationTimeUpdates = true;

                    if (OpenCifsServerFilePolicy.ShouldApplyExplicitFileTime(information.LastWriteTime))
                    {
                        if (!_FileStateTracker.TrySetTrackedFileTime(openRecord.Backend, openRecord.FullPath, FileTimeField.LastWrite, information.LastWriteTime))
                        {
                            return NtStatus.InvalidParameter;
                        }

                        mutatedWriteTime = true;
                    }
                }
            }

            if (information.FileAttributes != ProtocolFileAttributes.None)
            {
                openRecord.Backend.SetAttributes(openRecord.FullPath, OpenCifsServerFilePolicy.MapFileAttributes(information.FileAttributes));
                mutatedAttributes = true;
            }

            if (!explicitChangeTimeApplied &&
                !openRecord.SuppressChangeTimeUpdates &&
                (mutatedCreationTime || mutatedAccessTime || mutatedWriteTime || mutatedAttributes))
            {
                _FileStateTracker.SetTrackedChangeTime(openRecord.Backend, openRecord.FullPath, unchecked((ulong)DateTimeOffset.UtcNow.UtcDateTime.ToFileTimeUtc()));
            }

            if (mutatedCreationTime)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.Creation;
            }

            if (mutatedAccessTime)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.LastAccess;
            }

            if (mutatedWriteTime)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.LastWrite;
            }

            if (mutatedAttributes)
            {
                changeNotifyFilter |= FileNotifyChangeFilter.Attributes;
            }

            _PublishModifiedNotification(openRecord.FullPath, changeNotifyFilter);
            return NtStatus.Success;
        }

        public void ApplyFileAllocationInformation(ServerOpenRecord openRecord, FileAllocationInformation information)
        {
            if (openRecord.Stream == null)
            {
                throw new InvalidOperationException("A file stream is required for FILE_ALLOCATION_INFORMATION.");
            }

            ulong endOfFile = unchecked((ulong)Math.Max(0L, openRecord.Stream.Length));
            _FileStateTracker.SetDeclaredAllocationSize(openRecord.FullPath, information.AllocationSize, endOfFile);
            _PublishModifiedNotification(openRecord.FullPath, FileNotifyChangeFilter.Size | _FileStateTracker.NoteTimestampMutation(openRecord, updateChange: true));
        }

        public void ApplyFileEndOfFileInformation(ServerOpenRecord openRecord, FileEndOfFileInformation information)
        {
            if (openRecord.Stream == null)
            {
                throw new InvalidOperationException("A file stream is required for FILE_END_OF_FILE_INFORMATION.");
            }

            openRecord.Stream.SetLength(checked((long)information.EndOfFile));
            _FileStateTracker.EnsureDeclaredAllocationSize(openRecord.FullPath, information.EndOfFile);
            _PublishModifiedNotification(openRecord.FullPath, FileNotifyChangeFilter.Size | _FileStateTracker.NoteTimestampMutation(openRecord, updateLastWrite: true, updateChange: true));
        }

        public NtStatus ApplyDeletePendingState(ServerOpenRecord openRecord, bool deletePending)
        {
            if (!deletePending)
            {
                _OpenStateTracker.SetDeletePendingForPath(openRecord.FullPath, deletePending: false);
                return NtStatus.Success;
            }

            SystemFileAttributes existingAttributes;

            try
            {
                existingAttributes = openRecord.Backend.GetAttributes(openRecord.FullPath);
            }
            catch (DirectoryNotFoundException)
            {
                return NtStatus.ObjectNameNotFound;
            }
            catch (FileNotFoundException)
            {
                return NtStatus.ObjectNameNotFound;
            }
            catch (UnauthorizedAccessException)
            {
                return NtStatus.AccessDenied;
            }
            catch (IOException)
            {
                return NtStatus.AccessDenied;
            }

            if ((existingAttributes & SystemFileAttributes.ReadOnly) != 0)
            {
                return NtStatus.CannotDelete;
            }

            if (openRecord.IsDirectory)
            {
                try
                {
                    if (openRecord.Backend.EnumerateFileSystemInfos(openRecord.FullPath).Count != 0)
                    {
                        return NtStatus.DirectoryNotEmpty;
                    }
                }
                catch (DirectoryNotFoundException)
                {
                    return NtStatus.ObjectNameNotFound;
                }
                catch (UnauthorizedAccessException)
                {
                    return NtStatus.AccessDenied;
                }
                catch (IOException)
                {
                    return NtStatus.AccessDenied;
                }
            }

            _OpenStateTracker.SetDeletePendingForPath(openRecord.FullPath, deletePending: true);
            return NtStatus.Success;
        }

        public NtStatus ApplyRenameInformation(ServerOpenRecord openRecord, FileRenameInformationType2 information)
        {
            if (information.RootDirectory != 0)
            {
                return NtStatus.InvalidParameter;
            }

            if (openRecord.State.IsDeletePending)
            {
                return NtStatus.AccessDenied;
            }

            string normalizedPath = OpenCifsServerPathResolver.NormalizeRenamePath(information.FileName);

            if (!OpenCifsServerPathResolver.TryResolveShareFilePath(openRecord.ShareRootPath, normalizedPath, out string? destinationFullPath, out NtStatus destinationPathStatus) || destinationFullPath == null)
            {
                return destinationPathStatus;
            }

            string? destinationParent = Path.GetDirectoryName(destinationFullPath);

            if (string.IsNullOrEmpty(destinationParent) || !openRecord.Backend.DirectoryExists(destinationParent))
            {
                return NtStatus.ObjectPathNotFound;
            }

            if (openRecord.Backend.DirectoryExists(destinationFullPath))
            {
                return NtStatus.ObjectNameCollision;
            }

            if (openRecord.IsDirectory && _OpenStateTracker.HasOtherOpenRecordsWithinDirectory(openRecord.FullPath, openRecord.State.VolatileFileId))
            {
                return NtStatus.AccessDenied;
            }

            if (string.Equals(openRecord.FullPath, destinationFullPath, StringComparison.OrdinalIgnoreCase))
            {
                _OpenStateTracker.UpdateOpenRecordsForRename(openRecord.FullPath, destinationFullPath, normalizedPath);
                _FileStateTracker.NoteTimestampMutation(openRecord, updateChange: true);
                return NtStatus.Success;
            }

            bool destinationExists = openRecord.Backend.FileExists(destinationFullPath);

            if (destinationExists && !information.ReplaceIfExists)
            {
                return NtStatus.ObjectNameCollision;
            }

            if (destinationExists && _OpenStateTracker.HasOpenRecordsForPath(destinationFullPath))
            {
                return NtStatus.AccessDenied;
            }

            if (destinationExists)
            {
                _DeleteBackingObjectIfPresent(openRecord.Backend, destinationFullPath);
            }

            string sourceFullPath = openRecord.FullPath;

            if (openRecord.IsDirectory)
            {
                openRecord.Backend.Move(sourceFullPath, destinationFullPath, isDirectory: true);
                _FileStateTracker.MoveDirectoryTreeState(sourceFullPath, destinationFullPath);
            }
            else
            {
                openRecord.Backend.Move(sourceFullPath, destinationFullPath, isDirectory: false);
                _FileStateTracker.MoveFileState(sourceFullPath, destinationFullPath);
            }

            _OpenStateTracker.UpdateOpenRecordsForRename(sourceFullPath, destinationFullPath, normalizedPath);
            _FileStateTracker.NoteTimestampMutation(openRecord, updateChange: true);
            _PublishRenameNotification(sourceFullPath, destinationFullPath, openRecord.IsDirectory);
            return NtStatus.Success;
        }
    }
}
