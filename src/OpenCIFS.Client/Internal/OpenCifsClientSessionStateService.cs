namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientSessionStateService
    {
        public OpenCifsClientSessionStateService(OpenCifsClientSessionBootstrapState bootstrapState)
        {
            _BootstrapState = bootstrapState ?? throw new ArgumentNullException(nameof(bootstrapState), "BootstrapState cannot be null.");
        }

        public IDictionary<uint, TreeConnectState> Trees
        {
            get
            {
                return _Trees;
            }
        }

        public IDictionary<ulong, ClientOpenRecord> Opens
        {
            get
            {
                return _Opens;
            }
        }

        public uint[] ConnectedTreeIds
        {
            get
            {
                uint[] treeIds = new uint[_Trees.Count];
                _Trees.Keys.CopyTo(treeIds, 0);
                Array.Sort(treeIds);
                return treeIds;
            }
        }

        public int OpenCount
        {
            get
            {
                return _Opens.Count;
            }
        }

        public void EnsureAuthenticatedSession()
        {
            if (!_BootstrapState.SessionState.IsAuthenticated || _BootstrapState.SessionId == null)
            {
                throw new OpenCifsClientStateException("An authenticated session is required before file operations.");
            }
        }

        public void EnsureConnectedTree(uint treeId)
        {
            EnsureAuthenticatedSession();

            if (!_Trees.ContainsKey(treeId))
            {
                throw new OpenCifsClientStateException("The specified tree identifier is not connected on this client session.");
            }
        }

        public ClientOpenRecord GetTrackedOpen(ulong persistentFileId, ulong volatileFileId)
        {
            if (!_Opens.TryGetValue(volatileFileId, out ClientOpenRecord? openRecord) ||
                openRecord.State.PersistentFileId != persistentFileId)
            {
                throw new OpenCifsClientStateException("The specified file identifier is not open on this client session.");
            }

            return openRecord;
        }

        public ClientOpenRecord GetTrackedOpenByLeaseKey(uint treeId, byte[] leaseKey)
        {
            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            foreach (ClientOpenRecord openRecord in _Opens.Values)
            {
                if ((treeId == 0 || openRecord.TreeId == treeId) &&
                    openRecord.State.LeaseKey.AsSpan().SequenceEqual(leaseKey))
                {
                    return openRecord;
                }
            }

            throw new OpenCifsClientStateException("The specified lease key is not tracked on this client session.");
        }

        public string NormalizeOpenPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\').Trim('\\');

            if (normalizedPath.Length == 0)
            {
                throw new OpenCifsClientStateException("The file path must resolve to a non-empty relative path.");
            }

            return normalizedPath;
        }

        public void RemoveTrackedOpen(ulong persistentFileId, ulong volatileFileId)
        {
            if (_Opens.TryGetValue(volatileFileId, out ClientOpenRecord? openRecord) &&
                openRecord.State.PersistentFileId == persistentFileId)
            {
                openRecord.State.Dispose();
                _Opens.Remove(volatileFileId);
            }
        }

        public void RemoveOpensForTree(uint treeId)
        {
            List<ulong> volatileFileIds = new List<ulong>();

            foreach (KeyValuePair<ulong, ClientOpenRecord> entry in _Opens)
            {
                if (entry.Value.TreeId == treeId)
                {
                    volatileFileIds.Add(entry.Key);
                }
            }

            for (int index = 0; index < volatileFileIds.Count; index++)
            {
                ulong volatileFileId = volatileFileIds[index];
                ClientOpenRecord openRecord = _Opens[volatileFileId];
                openRecord.State.Dispose();
                _Opens.Remove(volatileFileId);
            }
        }

        public void ResetAuthenticatedState()
        {
            foreach (KeyValuePair<ulong, ClientOpenRecord> entry in _Opens)
            {
                entry.Value.State.Dispose();
            }

            _Opens.Clear();

            foreach (TreeConnectState treeState in _Trees.Values)
            {
                if (treeState.IsConnected)
                {
                    treeState.Disconnect();
                }

                treeState.Dispose();
            }

            _Trees.Clear();
            _BootstrapState.SessionState.Dispose();
            _BootstrapState.SessionState = new SessionState();
            _BootstrapState.SessionBaseKey = null;
            _BootstrapState.SessionSigningKey = null;
            _BootstrapState.SessionEncryptionKey = null;
            _BootstrapState.SessionDecryptionKey = null;
            _BootstrapState.StandardNegotiateMessage = null;
            _BootstrapState.NegotiatedServerCapabilities = Smb2GlobalCapabilities.None;
            _BootstrapState.NegotiatedServerSecurityMode = Smb2SecurityMode.SigningEnabled;
            _BootstrapState.IsSessionEncryptionRequired = false;
            _BootstrapState.IsSecureNegotiateValidated = false;
            _BootstrapState.SessionId = null;
        }

        private readonly OpenCifsClientSessionBootstrapState _BootstrapState;
        private readonly Dictionary<uint, TreeConnectState> _Trees = new Dictionary<uint, TreeConnectState>();
        private readonly Dictionary<ulong, ClientOpenRecord> _Opens = new Dictionary<ulong, ClientOpenRecord>();
    }
}
