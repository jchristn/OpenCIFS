namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;

    internal sealed class OpenCifsServerSessionOpenStateService
    {
        private readonly OpenCifsServerOpenCleanupService _OpenCleanupService;
        private readonly IReadOnlyDictionary<ulong, ServerSessionRecord> _Sessions;
        private readonly OpenCifsServerSharedState _SharedState;

        public OpenCifsServerSessionOpenStateService(
            IReadOnlyDictionary<ulong, ServerSessionRecord> sessions,
            OpenCifsServerSharedState sharedState,
            OpenCifsServerOpenCleanupService openCleanupService)
        {
            _Sessions = sessions ?? throw new ArgumentNullException(nameof(sessions), "Sessions cannot be null.");
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _OpenCleanupService = openCleanupService ?? throw new ArgumentNullException(nameof(openCleanupService), "OpenCleanupService cannot be null.");
        }

        public IEnumerable<ServerOpenRecord> EnumerateOpenRecords()
        {
            foreach (ServerSessionRecord sessionRecord in _Sessions.Values)
            {
                foreach (ServerOpenRecord openRecord in sessionRecord.Opens.Values)
                {
                    yield return openRecord;
                }
            }
        }

        public bool TryGetAuthenticatedTree(ulong sessionId, uint treeId, out ServerSessionRecord? sessionRecord)
        {
            ServerTreeRecord? treeRecord;
            return TryGetAuthenticatedTree(sessionId, treeId, out sessionRecord, out treeRecord);
        }

        public bool TryGetAuthenticatedTree(ulong sessionId, uint treeId, out ServerSessionRecord? sessionRecord, out ServerTreeRecord? treeRecord)
        {
            if (!_Sessions.TryGetValue(sessionId, out sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                sessionRecord = null;
                treeRecord = null;
                return false;
            }

            return sessionRecord.Trees.TryGetValue(treeId, out treeRecord);
        }

        public bool TryGetOpen(ServerSessionRecord sessionRecord, uint treeId, ulong persistentFileId, ulong volatileFileId, out ServerOpenRecord? openRecord)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            if (!sessionRecord.Opens.TryGetValue(volatileFileId, out openRecord))
            {
                openRecord = null;
                return false;
            }

            return openRecord.State.PersistentFileId == persistentFileId && openRecord.TreeId == treeId;
        }

        public bool TryGetOpenByLeaseKey(ServerSessionRecord sessionRecord, uint treeId, byte[] leaseKey, out ServerOpenRecord? openRecord)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            foreach (ServerOpenRecord candidate in sessionRecord.Opens.Values)
            {
                if (candidate.TreeId == treeId &&
                    candidate.LeaseRecord != null &&
                    ((ReadOnlySpan<byte>)candidate.LeaseRecord.LeaseKey.AsSpan()).SequenceEqual((ReadOnlySpan<byte>)leaseKey))
                {
                    openRecord = candidate;
                    return true;
                }
            }

            openRecord = null;
            return false;
        }

        public void UpdateLeaseStateForTrackedOpens(OpenCifsServerLeaseRecord leaseRecord)
        {
            if (leaseRecord == null)
            {
                throw new ArgumentNullException(nameof(leaseRecord), "LeaseRecord cannot be null.");
            }

            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in host.EnumerateOpenRecords())
                {
                    if (openRecord.LeaseRecord == leaseRecord)
                    {
                        openRecord.State.SetLeaseState(leaseRecord.LeaseState);
                    }
                }
            }
        }

        public void CleanupSessionRecord(ServerSessionRecord sessionRecord)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            List<ulong> volatileFileIds = new List<ulong>(sessionRecord.Opens.Keys);

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                _OpenCleanupService.CloseOpenRecord(sessionRecord, volatileFileIds[index]);
            }

            foreach (ServerTreeRecord treeRecord in sessionRecord.Trees.Values)
            {
                treeRecord.State.Dispose();
            }

            sessionRecord.Trees.Clear();
            sessionRecord.State.Dispose();
        }

        public void CleanupDisconnectedSessionRecord(ServerSessionRecord sessionRecord)
        {
            if (sessionRecord == null)
            {
                throw new ArgumentNullException(nameof(sessionRecord), "SessionRecord cannot be null.");
            }

            List<ulong> volatileFileIds = new List<ulong>(sessionRecord.Opens.Keys);

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                ulong volatileFileId = volatileFileIds[index];

                if (sessionRecord.Opens.TryGetValue(volatileFileId, out ServerOpenRecord? openRecord) && openRecord != null && CanDetachDurableOpen(openRecord))
                {
                    DetachDurableOpenRecord(sessionRecord, volatileFileId, openRecord);
                }
                else
                {
                    _OpenCleanupService.CloseOpenRecord(sessionRecord, volatileFileId);
                }
            }

            foreach (ServerTreeRecord treeRecord in sessionRecord.Trees.Values)
            {
                treeRecord.State.Dispose();
            }

            sessionRecord.Trees.Clear();
            sessionRecord.State.Dispose();
        }

        private void DetachDurableOpenRecord(ServerSessionRecord sessionRecord, ulong volatileFileId, ServerOpenRecord openRecord)
        {
            OpenCifsServerDurableOpenRecord durableOpenRecord = new OpenCifsServerDurableOpenRecord
            {
                PersistentFileId = openRecord.State.PersistentFileId,
                UsesDurableHandleV2 = openRecord.State.UsesDurableHandleV2,
                DurableCreateGuid = openRecord.State.DurableCreateGuid,
                DurableTimeoutMs = openRecord.State.DurableTimeoutMs,
                IsPersistent = openRecord.State.IsPersistent,
                DurableOwnerUserName = sessionRecord.UserName,
                DurableOwnerUserDomain = sessionRecord.UserDomain,
                ShareName = openRecord.ShareName,
                ShareRootPath = openRecord.ShareRootPath,
                Backend = openRecord.Backend,
                FullPath = openRecord.FullPath,
                RelativePath = openRecord.State.Path,
                DesiredAccess = openRecord.DesiredAccess,
                ShareAccess = openRecord.ShareAccess,
                CanRead = openRecord.CanRead,
                CanWrite = openRecord.CanWrite,
                CanReadData = openRecord.CanReadData,
                CanWriteData = openRecord.CanWriteData,
                CanDelete = openRecord.CanDelete,
                GrantedOplockLevel = openRecord.GrantedOplockLevel,
                LeaseRecord = openRecord.LeaseRecord,
                IsDeletePending = openRecord.State.IsDeletePending,
                SuppressAccessTimeUpdates = openRecord.SuppressAccessTimeUpdates,
                SuppressModificationTimeUpdates = openRecord.SuppressModificationTimeUpdates,
                SuppressChangeTimeUpdates = openRecord.SuppressChangeTimeUpdates,
                Stream = openRecord.Stream
            };

            for (int index = 0; index < openRecord.Locks.Count; index++)
            {
                ServerByteRangeLock byteRangeLock = openRecord.Locks[index];
                durableOpenRecord.Locks.Add(
                    new OpenCifsServerDetachedByteRangeLock
                    {
                        Offset = byteRangeLock.Offset,
                        Length = byteRangeLock.Length,
                        IsShared = byteRangeLock.IsShared
                    });
            }

            openRecord.Stream = null;
            openRecord.State.Dispose();
            sessionRecord.Opens.Remove(volatileFileId);
            _SharedState.PutDetachedDurableOpen(durableOpenRecord);
        }

        private static bool CanDetachDurableOpen(ServerOpenRecord openRecord)
        {
            return openRecord.State.IsDurable &&
                !openRecord.IsDirectory &&
                !openRecord.IsOplockBreakInProgress &&
                (openRecord.LeaseRecord == null || !openRecord.LeaseRecord.IsBreaking);
        }
    }
}
