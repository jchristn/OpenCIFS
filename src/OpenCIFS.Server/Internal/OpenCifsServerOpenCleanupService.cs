namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;
    using SystemFileAttributes = System.IO.FileAttributes;

    internal sealed class OpenCifsServerOpenCleanupService
    {
        private readonly OpenCifsServerFileStateTracker _FileStateTracker;
        private readonly OpenCifsServerOpenStateTracker _OpenStateTracker;
        private readonly Action<string, bool, FileNotifyAction> _PublishNameChangeNotification;
        private readonly Action<ulong> _QueueCancelledChangeNotifyResponsesForOpen;
        private readonly OpenCifsServerSharedState _SharedState;

        public OpenCifsServerOpenCleanupService(
            OpenCifsServerSharedState sharedState,
            OpenCifsServerOpenStateTracker openStateTracker,
            OpenCifsServerFileStateTracker fileStateTracker,
            Action<ulong> queueCancelledChangeNotifyResponsesForOpen,
            Action<string, bool, FileNotifyAction> publishNameChangeNotification)
        {
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _OpenStateTracker = openStateTracker ?? throw new ArgumentNullException(nameof(openStateTracker), "OpenStateTracker cannot be null.");
            _FileStateTracker = fileStateTracker ?? throw new ArgumentNullException(nameof(fileStateTracker), "FileStateTracker cannot be null.");
            _QueueCancelledChangeNotifyResponsesForOpen = queueCancelledChangeNotifyResponsesForOpen ?? throw new ArgumentNullException(nameof(queueCancelledChangeNotifyResponsesForOpen), "QueueCancelledChangeNotifyResponsesForOpen cannot be null.");
            _PublishNameChangeNotification = publishNameChangeNotification ?? throw new ArgumentNullException(nameof(publishNameChangeNotification), "PublishNameChangeNotification cannot be null.");
        }

        public void CleanupTreeOpenRecords(ServerSessionRecord sessionRecord, uint treeId)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            List<ulong> volatileFileIds = new List<ulong>();

            foreach (KeyValuePair<ulong, ServerOpenRecord> entry in sessionRecord.Opens)
            {
                if (entry.Value.TreeId == treeId)
                {
                    volatileFileIds.Add(entry.Key);
                }
            }

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                CloseOpenRecord(sessionRecord, volatileFileIds[index]);
            }
        }

        public void CloseOpenRecord(ServerSessionRecord sessionRecord, ulong volatileFileId)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            if (sessionRecord.Opens.TryGetValue(volatileFileId, out ServerOpenRecord? openRecord))
            {
                string fullPath = openRecord.FullPath;
                bool deletePending = openRecord.State.IsDeletePending;
                bool isDirectory = openRecord.IsDirectory;
                OpenCifsServerLeaseRecord? leaseRecord = openRecord.LeaseRecord;
                _QueueCancelledChangeNotifyResponsesForOpen(volatileFileId);
                openRecord.Dispose();
                sessionRecord.Opens.Remove(volatileFileId);

                if (leaseRecord != null)
                {
                    leaseRecord.OpenCount = Math.Max(0, leaseRecord.OpenCount - 1);
                    _SharedState.RemoveLeaseRecordIfUnused(leaseRecord);
                }

                if (deletePending && !_OpenStateTracker.HasOpenRecordsForPath(fullPath))
                {
                    if (DeleteBackingObjectIfPresent(openRecord.Backend, fullPath))
                    {
                        _PublishNameChangeNotification(fullPath, isDirectory, FileNotifyAction.Removed);
                    }
                }
            }
        }

        public bool DeleteBackingObjectIfPresent(OpenCifsServerShareBackend backend, string fullPath)
        {
            if (backend == null)
            {
                throw new ArgumentNullException(nameof(backend), "Backend cannot be null.");
            }

            if (fullPath == null)
            {
                throw new ArgumentNullException(nameof(fullPath), "FullPath cannot be null.");
            }

            if (backend.FileExists(fullPath))
            {
                try
                {
                    backend.SetAttributes(fullPath, SystemFileAttributes.Normal);
                }
                catch (FileNotFoundException)
                {
                    return false;
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (IOException)
                {
                }

                try
                {
                    backend.DeleteFileIfPresent(fullPath);
                }
                catch (FileNotFoundException)
                {
                    return false;
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }

                _FileStateTracker.RemovePathState(fullPath);
                return true;
            }

            if (backend.DirectoryExists(fullPath))
            {
                try
                {
                    backend.DeleteDirectoryIfPresent(fullPath, recursive: false);
                }
                catch (DirectoryNotFoundException)
                {
                    return false;
                }
                catch (UnauthorizedAccessException)
                {
                    return false;
                }
                catch (IOException)
                {
                    return false;
                }

                _FileStateTracker.RemovePathState(fullPath);
                return true;
            }

            _FileStateTracker.RemovePathState(fullPath);
            return false;
        }
    }
}
