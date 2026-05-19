namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerOpenStateTracker
    {
        private const uint FileShareRead = 0x00000001U;
        private const uint FileShareWrite = 0x00000002U;
        private const uint FileShareDelete = 0x00000004U;

        private readonly Func<OpenCifsServerHost, IEnumerable<ServerOpenRecord>> _EnumerateOpenRecords;
        private readonly OpenCifsServerSharedState _SharedState;

        public OpenCifsServerOpenStateTracker(OpenCifsServerSharedState sharedState, Func<OpenCifsServerHost, IEnumerable<ServerOpenRecord>> enumerateOpenRecords)
        {
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _EnumerateOpenRecords = enumerateOpenRecords ?? throw new ArgumentNullException(nameof(enumerateOpenRecords), "EnumerateOpenRecords cannot be null.");
        }

        public List<ServerOpenRecord> GetOpenRecordsForPath(string fullPath)
        {
            List<ServerOpenRecord> matchingOpens = new List<ServerOpenRecord>();

            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in _EnumerateOpenRecords(host))
                {
                    if (string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                    {
                        matchingOpens.Add(openRecord);
                    }
                }
            }

            return matchingOpens;
        }

        public bool HasOpenRecordsForPath(string fullPath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in _EnumerateOpenRecords(host))
                {
                    if (string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public bool HasOtherOpenRecordsWithinDirectory(string directoryFullPath, ulong excludedVolatileFileId)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in _EnumerateOpenRecords(host))
                {
                    if (openRecord.State.VolatileFileId == excludedVolatileFileId)
                    {
                        continue;
                    }

                    if (string.Equals(openRecord.FullPath, directoryFullPath, StringComparison.OrdinalIgnoreCase) ||
                        OpenCifsServerPathResolver.IsPathDescendantOf(openRecord.FullPath, directoryFullPath))
                    {
                        return true;
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (string.Equals(durableOpenRecord.FullPath, directoryFullPath, StringComparison.OrdinalIgnoreCase) ||
                    OpenCifsServerPathResolver.IsPathDescendantOf(durableOpenRecord.FullPath, directoryFullPath))
                {
                    return true;
                }
            }

            return false;
        }

        public bool HasDeletePendingConflict(string fullPath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in _EnumerateOpenRecords(host))
                {
                    if (!openRecord.State.IsDeletePending)
                    {
                        continue;
                    }

                    if (string.Equals(openRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                    {
                        return true;
                    }

                    if (openRecord.IsDirectory && OpenCifsServerPathResolver.IsPathDescendantOf(fullPath, openRecord.FullPath))
                    {
                        return true;
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (!durableOpenRecord.IsDeletePending)
                {
                    continue;
                }

                if (string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public bool TryValidateCreateOpenSemantics(string fullPath, uint desiredAccess, uint shareAccess, out NtStatus status)
        {
            if (HasDeletePendingConflict(fullPath))
            {
                status = NtStatus.DeletePending;
                return false;
            }

            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                if (matchingOpens[index].State.IsDeletePending)
                {
                    status = NtStatus.DeletePending;
                    return false;
                }
            }

            bool requestRead = OpenCifsServerFilePolicy.CanReadData(desiredAccess);
            bool requestWrite = OpenCifsServerFilePolicy.CanWrite(desiredAccess);
            bool requestDelete = OpenCifsServerFilePolicy.CanDelete(desiredAccess);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];

                if (requestRead && (openRecord.ShareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestWrite && (openRecord.ShareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestDelete && (openRecord.ShareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (openRecord.CanReadData && (shareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (openRecord.CanWrite && (shareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (openRecord.CanDelete && (shareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                OpenCifsServerDurableOpenRecord durableOpenRecord = detachedDurableOpens[index];

                if (!string.Equals(durableOpenRecord.FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (durableOpenRecord.IsDeletePending)
                {
                    status = NtStatus.DeletePending;
                    return false;
                }

                if (requestRead && (durableOpenRecord.ShareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestWrite && (durableOpenRecord.ShareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (requestDelete && (durableOpenRecord.ShareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (durableOpenRecord.CanReadData && (shareAccess & FileShareRead) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (durableOpenRecord.CanWrite && (shareAccess & FileShareWrite) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }

                if (durableOpenRecord.CanDelete && (shareAccess & FileShareDelete) == 0)
                {
                    status = NtStatus.SharingViolation;
                    return false;
                }
            }

            status = NtStatus.Success;
            return true;
        }

        public bool HasConflictingOpenForLease(string fullPath, OpenCifsServerLeaseRecord? excludedLeaseRecord)
        {
            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];

                if (excludedLeaseRecord != null &&
                    ReferenceEquals(openRecord.LeaseRecord, excludedLeaseRecord))
                {
                    continue;
                }

                return true;
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        public void SetDeletePendingForPath(string fullPath, bool deletePending)
        {
            List<ServerOpenRecord> matchingOpens = GetOpenRecordsForPath(fullPath);

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                matchingOpens[index].State.SetDeletePending(deletePending);
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, fullPath, StringComparison.OrdinalIgnoreCase))
                {
                    detachedDurableOpens[index].IsDeletePending = deletePending;
                }
            }
        }

        public void UpdateOpenRecordsForRename(string oldFullPath, string newFullPath, string newRelativePath)
        {
            foreach (OpenCifsServerHost host in _SharedState.Hosts)
            {
                foreach (ServerOpenRecord openRecord in _EnumerateOpenRecords(host))
                {
                    if (string.Equals(openRecord.FullPath, oldFullPath, StringComparison.OrdinalIgnoreCase))
                    {
                        openRecord.FullPath = newFullPath;
                        openRecord.State.UpdatePath(newRelativePath);
                    }
                }
            }

            OpenCifsServerDurableOpenRecord[] detachedDurableOpens = _SharedState.DetachedDurableOpensSnapshot;

            for (int index = 0; index < detachedDurableOpens.Length; index++)
            {
                if (string.Equals(detachedDurableOpens[index].FullPath, oldFullPath, StringComparison.OrdinalIgnoreCase))
                {
                    detachedDurableOpens[index].FullPath = newFullPath;
                    detachedDurableOpens[index].RelativePath = newRelativePath;
                }
            }
        }
    }
}
