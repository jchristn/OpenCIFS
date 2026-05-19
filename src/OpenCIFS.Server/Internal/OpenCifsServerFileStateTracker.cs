namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;
    using SystemFileAttributes = System.IO.FileAttributes;

    internal sealed class OpenCifsServerFileStateTracker
    {
        private readonly Dictionary<string, ulong> _DeclaredAllocationSizes = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, TrackedFileTimestamps> _TrackedFileTimestamps = new Dictionary<string, TrackedFileTimestamps>(StringComparer.OrdinalIgnoreCase);

        public void EnsureDeclaredAllocationSize(string fullPath, ulong endOfFile)
        {
            if (_DeclaredAllocationSizes.TryGetValue(fullPath, out ulong allocationSize) && allocationSize >= endOfFile)
            {
                return;
            }

            _DeclaredAllocationSizes[fullPath] = endOfFile;
        }

        public void SetDeclaredAllocationSize(string fullPath, ulong requestedAllocationSize, ulong endOfFile)
        {
            _DeclaredAllocationSizes[fullPath] = Math.Max(requestedAllocationSize, endOfFile);
        }

        public void MoveFileState(string oldFullPath, string newFullPath)
        {
            MoveDeclaredAllocationSize(oldFullPath, newFullPath);
            MoveTrackedFileTimestamp(oldFullPath, newFullPath);
        }

        public void MoveDirectoryTreeState(string oldDirectoryFullPath, string newDirectoryFullPath)
        {
            MoveTrackedFileTimestamp(oldDirectoryFullPath, newDirectoryFullPath);
            MoveDescendantAllocationSizes(oldDirectoryFullPath, newDirectoryFullPath);
            MoveDescendantTrackedFileTimestamps(oldDirectoryFullPath, newDirectoryFullPath);
        }

        public bool TrySetTrackedFileTime(OpenCifsServerShareBackend backend, string fullPath, FileTimeField field, ulong fileTime)
        {
            if (!OpenCifsServerFilePolicy.TryConvertFileTimeToUtcDateTime(fileTime, out DateTime utcValue))
            {
                return false;
            }

            TrackedFileTimestamps timestamps = GetOrCreateTrackedFileTimestamps(backend, fullPath);

            switch (field)
            {
                case FileTimeField.Creation:
                    OpenCifsServerFilePolicy.SetCreationTimeUtc(backend, fullPath, utcValue);
                    timestamps.CreationTime = fileTime;
                    break;
                case FileTimeField.LastAccess:
                    OpenCifsServerFilePolicy.SetLastAccessTimeUtc(backend, fullPath, utcValue);
                    timestamps.LastAccessTime = fileTime;
                    break;
                case FileTimeField.LastWrite:
                    OpenCifsServerFilePolicy.SetLastWriteTimeUtc(backend, fullPath, utcValue);
                    timestamps.LastWriteTime = fileTime;
                    break;
                case FileTimeField.Change:
                    timestamps.ChangeTime = fileTime;
                    break;
                default:
                    throw new InvalidOperationException("Unknown file time field.");
            }

            _TrackedFileTimestamps[fullPath] = timestamps;
            return true;
        }

        public FileNotifyChangeFilter NoteTimestampMutation(ServerOpenRecord openRecord, bool updateLastAccess = false, bool updateLastWrite = false, bool updateChange = false)
        {
            if ((updateLastAccess && openRecord.SuppressAccessTimeUpdates) ||
                !updateLastAccess)
            {
                updateLastAccess = false;
            }

            if ((updateLastWrite && openRecord.SuppressModificationTimeUpdates) ||
                !updateLastWrite)
            {
                updateLastWrite = false;
            }

            if ((updateChange && openRecord.SuppressChangeTimeUpdates) ||
                !updateChange)
            {
                updateChange = false;
            }

            if (!updateLastAccess && !updateLastWrite && !updateChange)
            {
                return FileNotifyChangeFilter.None;
            }

            ulong currentTime = unchecked((ulong)DateTimeOffset.UtcNow.UtcDateTime.ToFileTimeUtc());
            DateTime currentUtcValue = DateTime.FromFileTimeUtc(unchecked((long)currentTime));
            TrackedFileTimestamps timestamps = GetOrCreateTrackedFileTimestamps(openRecord.Backend, openRecord.FullPath);
            FileNotifyChangeFilter changeNotifyFilter = FileNotifyChangeFilter.None;

            if (updateLastAccess)
            {
                OpenCifsServerFilePolicy.SetLastAccessTimeUtc(openRecord.Backend, openRecord.FullPath, currentUtcValue);
                timestamps.LastAccessTime = currentTime;
                changeNotifyFilter |= FileNotifyChangeFilter.LastAccess;
            }

            if (updateLastWrite)
            {
                OpenCifsServerFilePolicy.SetLastWriteTimeUtc(openRecord.Backend, openRecord.FullPath, currentUtcValue);
                timestamps.LastWriteTime = currentTime;
                changeNotifyFilter |= FileNotifyChangeFilter.LastWrite;
            }

            if (updateChange)
            {
                timestamps.ChangeTime = currentTime;
            }

            _TrackedFileTimestamps[openRecord.FullPath] = timestamps;
            return changeNotifyFilter;
        }

        public void SetTrackedChangeTime(OpenCifsServerShareBackend backend, string fullPath, ulong fileTime)
        {
            TrackedFileTimestamps timestamps = GetOrCreateTrackedFileTimestamps(backend, fullPath);
            timestamps.ChangeTime = fileTime;
            _TrackedFileTimestamps[fullPath] = timestamps;
        }

        public void RemovePathState(string fullPath)
        {
            _DeclaredAllocationSizes.Remove(fullPath);
            _TrackedFileTimestamps.Remove(fullPath);
        }

        public FileMetadata BuildFileMetadata(OpenCifsServerShareBackend backend, string fullPath)
        {
            TrackedFileTimestamps trackedFileTimestamps = GetOrCreateTrackedFileTimestamps(backend, fullPath);

            if (backend.DirectoryExists(fullPath))
            {
                DirectoryInfo directoryInfo = (DirectoryInfo)backend.GetFileSystemInfo(fullPath);
                directoryInfo.Refresh();
                return new FileMetadata
                {
                    CreationTime = trackedFileTimestamps.CreationTime,
                    LastAccessTime = trackedFileTimestamps.LastAccessTime,
                    LastWriteTime = trackedFileTimestamps.LastWriteTime,
                    ChangeTime = trackedFileTimestamps.ChangeTime,
                    AllocationSize = 0,
                    EndOfFile = 0,
                    FileAttributes = OpenCifsServerFilePolicy.MapFileAttributes(directoryInfo.Attributes)
                };
            }

            FileInfo fileInfo = (FileInfo)backend.GetFileSystemInfo(fullPath);
            fileInfo.Refresh();
            long endOfFile = fileInfo.Exists ? fileInfo.Length : 0;
            ulong effectiveEndOfFile = unchecked((ulong)Math.Max(0L, endOfFile));
            ulong allocationSize = effectiveEndOfFile;

            if (_DeclaredAllocationSizes.TryGetValue(fullPath, out ulong declaredAllocationSize))
            {
                allocationSize = Math.Max(declaredAllocationSize, effectiveEndOfFile);
            }

            return new FileMetadata
            {
                CreationTime = trackedFileTimestamps.CreationTime,
                LastAccessTime = trackedFileTimestamps.LastAccessTime,
                LastWriteTime = trackedFileTimestamps.LastWriteTime,
                ChangeTime = trackedFileTimestamps.ChangeTime,
                AllocationSize = allocationSize,
                EndOfFile = effectiveEndOfFile,
                FileAttributes = OpenCifsServerFilePolicy.MapFileAttributes(fileInfo.Exists ? fileInfo.Attributes : SystemFileAttributes.Normal)
            };
        }

        private void MoveDeclaredAllocationSize(string oldFullPath, string newFullPath)
        {
            if (_DeclaredAllocationSizes.TryGetValue(oldFullPath, out ulong allocationSize))
            {
                _DeclaredAllocationSizes.Remove(oldFullPath);
                _DeclaredAllocationSizes[newFullPath] = allocationSize;
            }
        }

        private void MoveDescendantAllocationSizes(string oldDirectoryFullPath, string newDirectoryFullPath)
        {
            string oldPrefix = oldDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? oldDirectoryFullPath
                : oldDirectoryFullPath + Path.DirectorySeparatorChar;
            string newPrefix = newDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? newDirectoryFullPath
                : newDirectoryFullPath + Path.DirectorySeparatorChar;

            List<KeyValuePair<string, ulong>> movedEntries = new List<KeyValuePair<string, ulong>>();

            foreach (KeyValuePair<string, ulong> entry in _DeclaredAllocationSizes)
            {
                if (entry.Key.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    string suffix = entry.Key.Substring(oldPrefix.Length);
                    movedEntries.Add(new KeyValuePair<string, ulong>(newPrefix + suffix, entry.Value));
                }
            }

            for (int index = movedEntries.Count - 1; index >= 0; index--)
            {
                string suffix = movedEntries[index].Key.Substring(newPrefix.Length);
                _DeclaredAllocationSizes.Remove(oldPrefix + suffix);
            }

            for (int index = 0; index < movedEntries.Count; index++)
            {
                _DeclaredAllocationSizes[movedEntries[index].Key] = movedEntries[index].Value;
            }
        }

        private TrackedFileTimestamps GetOrCreateTrackedFileTimestamps(OpenCifsServerShareBackend backend, string fullPath)
        {
            if (_TrackedFileTimestamps.TryGetValue(fullPath, out TrackedFileTimestamps timestamps))
            {
                return timestamps;
            }

            timestamps = ReadActualTrackedFileTimestamps(backend, fullPath);
            _TrackedFileTimestamps[fullPath] = timestamps;
            return timestamps;
        }

        private TrackedFileTimestamps ReadActualTrackedFileTimestamps(OpenCifsServerShareBackend backend, string fullPath)
        {
            if (backend.DirectoryExists(fullPath))
            {
                DirectoryInfo directoryInfo = (DirectoryInfo)backend.GetFileSystemInfo(fullPath);
                directoryInfo.Refresh();
                ulong creationTime = unchecked((ulong)directoryInfo.CreationTimeUtc.ToFileTimeUtc());
                ulong lastAccessTime = unchecked((ulong)directoryInfo.LastAccessTimeUtc.ToFileTimeUtc());
                ulong lastWriteTime = unchecked((ulong)directoryInfo.LastWriteTimeUtc.ToFileTimeUtc());
                return new TrackedFileTimestamps
                {
                    CreationTime = creationTime,
                    LastAccessTime = lastAccessTime,
                    LastWriteTime = lastWriteTime,
                    ChangeTime = lastWriteTime
                };
            }

            FileInfo fileInfo = (FileInfo)backend.GetFileSystemInfo(fullPath);
            fileInfo.Refresh();
            ulong fileTimeCreation = fileInfo.Exists ? unchecked((ulong)fileInfo.CreationTimeUtc.ToFileTimeUtc()) : 0;
            ulong fileTimeAccess = fileInfo.Exists ? unchecked((ulong)fileInfo.LastAccessTimeUtc.ToFileTimeUtc()) : 0;
            ulong fileTimeWrite = fileInfo.Exists ? unchecked((ulong)fileInfo.LastWriteTimeUtc.ToFileTimeUtc()) : 0;
            return new TrackedFileTimestamps
            {
                CreationTime = fileTimeCreation,
                LastAccessTime = fileTimeAccess,
                LastWriteTime = fileTimeWrite,
                ChangeTime = fileTimeWrite
            };
        }

        private void MoveTrackedFileTimestamp(string oldFullPath, string newFullPath)
        {
            if (_TrackedFileTimestamps.TryGetValue(oldFullPath, out TrackedFileTimestamps timestamps))
            {
                _TrackedFileTimestamps.Remove(oldFullPath);
                _TrackedFileTimestamps[newFullPath] = timestamps;
            }
        }

        private void MoveDescendantTrackedFileTimestamps(string oldDirectoryFullPath, string newDirectoryFullPath)
        {
            string oldPrefix = oldDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? oldDirectoryFullPath
                : oldDirectoryFullPath + Path.DirectorySeparatorChar;
            string newPrefix = newDirectoryFullPath.EndsWith(Path.DirectorySeparatorChar.ToString(), StringComparison.Ordinal)
                ? newDirectoryFullPath
                : newDirectoryFullPath + Path.DirectorySeparatorChar;

            List<KeyValuePair<string, TrackedFileTimestamps>> movedEntries = new List<KeyValuePair<string, TrackedFileTimestamps>>();

            foreach (KeyValuePair<string, TrackedFileTimestamps> entry in _TrackedFileTimestamps)
            {
                if (entry.Key.StartsWith(oldPrefix, StringComparison.OrdinalIgnoreCase))
                {
                    string suffix = entry.Key.Substring(oldPrefix.Length);
                    movedEntries.Add(new KeyValuePair<string, TrackedFileTimestamps>(newPrefix + suffix, entry.Value));
                }
            }

            for (int index = movedEntries.Count - 1; index >= 0; index--)
            {
                string suffix = movedEntries[index].Key.Substring(newPrefix.Length);
                _TrackedFileTimestamps.Remove(oldPrefix + suffix);
            }

            for (int index = 0; index < movedEntries.Count; index++)
            {
                _TrackedFileTimestamps[movedEntries[index].Key] = movedEntries[index].Value;
            }
        }
    }
}
