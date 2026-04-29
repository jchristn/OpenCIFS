namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Shared server-wide state used by connection-scoped direct-TCP hosts.
    /// </summary>
    public sealed class OpenCifsServerSharedState
    {
        internal object SyncRoot { get; } = new object();

        internal IReadOnlyCollection<OpenCifsServerHost> Hosts
        {
            get
            {
                return _Hosts;
            }
        }

        internal OpenCifsServerDurableOpenRecord[] DetachedDurableOpensSnapshot
        {
            get
            {
                lock (SyncRoot)
                {
                    OpenCifsServerDurableOpenRecord[] snapshot = new OpenCifsServerDurableOpenRecord[_DetachedDurableOpens.Count];
                    _DetachedDurableOpens.Values.CopyTo(snapshot, 0);
                    return snapshot;
                }
            }
        }

        internal OpenCifsServerLeaseRecord[] LeaseRecordsSnapshot
        {
            get
            {
                lock (SyncRoot)
                {
                    OpenCifsServerLeaseRecord[] snapshot = new OpenCifsServerLeaseRecord[_LeaseRecords.Count];
                    _LeaseRecords.Values.CopyTo(snapshot, 0);
                    return snapshot;
                }
            }
        }

        internal ulong AllocateFileId()
        {
            lock (SyncRoot)
            {
                return _NextFileId++;
            }
        }

        internal void RegisterHost(OpenCifsServerHost host)
        {
            if (host == null)
            {
                throw new ArgumentNullException(nameof(host), "Host cannot be null.");
            }

            lock (SyncRoot)
            {
                _Hosts.Add(host);
            }
        }

        internal void UnregisterHost(OpenCifsServerHost host)
        {
            if (host == null)
            {
                throw new ArgumentNullException(nameof(host), "Host cannot be null.");
            }

            lock (SyncRoot)
            {
                _Hosts.Remove(host);
            }
        }

        internal void PutDetachedDurableOpen(OpenCifsServerDurableOpenRecord durableOpenRecord)
        {
            if (durableOpenRecord == null)
            {
                throw new ArgumentNullException(nameof(durableOpenRecord), "DurableOpenRecord cannot be null.");
            }

            lock (SyncRoot)
            {
                if (_DetachedDurableOpens.ContainsKey(durableOpenRecord.PersistentFileId))
                {
                    throw new InvalidOperationException("A detached durable open with the same persistent file identifier is already registered.");
                }

                _DetachedDurableOpens[durableOpenRecord.PersistentFileId] = durableOpenRecord;
            }
        }

        internal bool TryTakeDetachedDurableOpen(ulong persistentFileId, out OpenCifsServerDurableOpenRecord? durableOpenRecord)
        {
            lock (SyncRoot)
            {
                if (_DetachedDurableOpens.TryGetValue(persistentFileId, out durableOpenRecord))
                {
                    _DetachedDurableOpens.Remove(persistentFileId);
                    return true;
                }
            }

            durableOpenRecord = null;
            return false;
        }

        internal bool TryGetLeaseRecord(Guid clientGuid, byte[] leaseKey, out OpenCifsServerLeaseRecord? leaseRecord)
        {
            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            lock (SyncRoot)
            {
                return _LeaseRecords.TryGetValue(GetLeaseRecordKey(clientGuid, leaseKey), out leaseRecord);
            }
        }

        internal OpenCifsServerLeaseRecord GetOrAddLeaseRecord(Guid clientGuid, byte[] leaseKey, string fullPath)
        {
            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(fullPath))
            {
                throw new ArgumentNullException(nameof(fullPath), "FullPath cannot be null or whitespace.");
            }

            lock (SyncRoot)
            {
                string key = GetLeaseRecordKey(clientGuid, leaseKey);

                if (_LeaseRecords.TryGetValue(key, out OpenCifsServerLeaseRecord? existingLeaseRecord))
                {
                    return existingLeaseRecord;
                }

                OpenCifsServerLeaseRecord leaseRecord = new OpenCifsServerLeaseRecord
                {
                    ClientGuid = clientGuid,
                    LeaseKey = (byte[])leaseKey.Clone(),
                    FullPath = fullPath
                };
                _LeaseRecords[key] = leaseRecord;
                return leaseRecord;
            }
        }

        internal void RemoveLeaseRecordIfUnused(OpenCifsServerLeaseRecord leaseRecord)
        {
            if (leaseRecord == null)
            {
                throw new ArgumentNullException(nameof(leaseRecord), "LeaseRecord cannot be null.");
            }

            lock (SyncRoot)
            {
                if (leaseRecord.OpenCount != 0)
                {
                    return;
                }

                _LeaseRecords.Remove(GetLeaseRecordKey(leaseRecord.ClientGuid, leaseRecord.LeaseKey));
            }
        }

        private readonly HashSet<OpenCifsServerHost> _Hosts = new HashSet<OpenCifsServerHost>();
        private readonly Dictionary<ulong, OpenCifsServerDurableOpenRecord> _DetachedDurableOpens = new Dictionary<ulong, OpenCifsServerDurableOpenRecord>();
        private readonly Dictionary<string, OpenCifsServerLeaseRecord> _LeaseRecords = new Dictionary<string, OpenCifsServerLeaseRecord>(StringComparer.Ordinal);
        private ulong _NextFileId = 1;

        private static string GetLeaseRecordKey(Guid clientGuid, byte[] leaseKey)
        {
            return clientGuid.ToString("D", System.Globalization.CultureInfo.InvariantCulture) + ":" + Convert.ToHexString(leaseKey);
        }
    }
}
