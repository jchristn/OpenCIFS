namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Open handle returned by the managed direct-TCP client connection surface.
    /// </summary>
    public sealed class OpenCifsClientOpenHandle
    {
        /// <summary>
        /// Initialize a tracked open handle.
        /// </summary>
        /// <param name="connectionId">Owning connection identifier.</param>
        /// <param name="sessionGeneration">Owning session generation.</param>
        /// <param name="treeHandle">Owning tree handle.</param>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="path">Opened relative path.</param>
        /// <param name="isDirectory">Whether the open references a directory.</param>
        /// <param name="oplockLevel">Tracked oplock level for the open.</param>
        /// <param name="desiredAccess">Original desired access mask.</param>
        /// <param name="fileAttributes">Original create-time file attributes.</param>
        /// <param name="shareAccess">Original share-access mask.</param>
        /// <param name="createDisposition">Original create disposition.</param>
        /// <param name="createOptions">Original create options.</param>
        /// <param name="requestedOplockLevel">Original requested oplock level.</param>
        /// <param name="isDurable">Whether the server granted durable reconnect state for the open.</param>
        /// <param name="usesDurableHandleV2">Whether the open uses SMB 3.x durable-handle v2 contexts.</param>
        /// <param name="durableCreateGuid">SMB 3.x durable-handle create GUID when available.</param>
        /// <param name="durableTimeoutMs">Granted durable reconnect timeout in milliseconds.</param>
        /// <param name="isPersistent">Whether the durable open is persistent.</param>
        /// <param name="leaseKey">Lease key bytes for an SMB 2.1 lease-backed open.</param>
        /// <param name="leaseState">Current SMB 2.1 lease state.</param>
        internal OpenCifsClientOpenHandle(
            Guid connectionId,
            long sessionGeneration,
            OpenCifsClientTreeHandle treeHandle,
            ulong persistentFileId,
            ulong volatileFileId,
            string path,
            bool isDirectory,
            Smb2OplockLevel oplockLevel,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel,
            bool isDurable,
            bool usesDurableHandleV2,
            Guid durableCreateGuid,
            uint durableTimeoutMs,
            bool isPersistent,
            byte[] leaseKey,
            Smb2LeaseState leaseState)
        {
            if (treeHandle == null)
            {
                throw new ArgumentNullException(nameof(treeHandle), "TreeHandle cannot be null.");
            }

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            ConnectionId = connectionId;
            SessionGeneration = sessionGeneration;
            TreeHandle = treeHandle;
            PersistentFileId = persistentFileId;
            VolatileFileId = volatileFileId;
            Path = path;
            IsDirectory = isDirectory;
            OplockLevel = oplockLevel;
            DesiredAccess = desiredAccess;
            FileAttributes = fileAttributes;
            ShareAccess = shareAccess;
            CreateDisposition = createDisposition;
            CreateOptions = createOptions;
            RequestedOplockLevel = requestedOplockLevel;
            IsDurable = isDurable;
            UsesDurableHandleV2 = usesDurableHandleV2;
            DurableCreateGuid = durableCreateGuid;
            DurableTimeoutMs = durableTimeoutMs;
            IsPersistent = isPersistent;
            CanReconnectDurably = isDurable && (!usesDurableHandleV2 || durableCreateGuid != Guid.Empty);
            LeaseKey = leaseKey == null ? Array.Empty<byte>() : (byte[])leaseKey.Clone();
            LeaseState = leaseState;
        }

        /// <summary>
        /// Share name that owns this open.
        /// </summary>
        public string ShareName
        {
            get
            {
                return TreeHandle.ShareName;
            }
        }

        /// <summary>
        /// Server-assigned tree identifier that owns this open.
        /// </summary>
        public uint TreeId
        {
            get
            {
                return TreeHandle.TreeId;
            }
        }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; }

        /// <summary>
        /// Opened relative path.
        /// </summary>
        public string Path { get; private set; }

        /// <summary>
        /// Whether the open references a directory.
        /// </summary>
        public bool IsDirectory { get; }

        /// <summary>
        /// Whether this open is delete-pending.
        /// </summary>
        public bool IsDeletePending { get; private set; }

        /// <summary>
        /// Current oplock level tracked for this open.
        /// </summary>
        public Smb2OplockLevel OplockLevel { get; private set; }

        /// <summary>
        /// Lease key bytes when the open is backed by an SMB 2.1 lease.
        /// </summary>
        public byte[] LeaseKey { get; }

        /// <summary>
        /// Current SMB 2.1 lease state for the open.
        /// </summary>
        public Smb2LeaseState LeaseState { get; private set; }

        /// <summary>
        /// Whether the server granted this open durable reconnect state.
        /// </summary>
        public bool IsDurable { get; private set; }

        /// <summary>
        /// Whether the open uses SMB 3.x durable-handle v2 contexts.
        /// </summary>
        public bool UsesDurableHandleV2 { get; }

        /// <summary>
        /// Granted durable reconnect timeout in milliseconds.
        /// </summary>
        public uint DurableTimeoutMs { get; }

        /// <summary>
        /// Whether the durable open is persistent.
        /// </summary>
        public bool IsPersistent { get; }

        /// <summary>
        /// Whether this open can currently be used as a durable reconnect token.
        /// </summary>
        public bool CanReconnectDurably { get; private set; }

        /// <summary>
        /// Whether this open handle has been closed and can no longer be used.
        /// </summary>
        public bool IsClosed { get; private set; }

        internal Guid ConnectionId { get; }

        internal long SessionGeneration { get; }

        internal OpenCifsClientTreeHandle TreeHandle { get; }

        internal uint DesiredAccess { get; }

        internal FileAttributes FileAttributes { get; }

        internal uint ShareAccess { get; }

        internal Smb2CreateDisposition CreateDisposition { get; }

        internal Smb2CreateOptions CreateOptions { get; }

        internal Smb2OplockLevel RequestedOplockLevel { get; }

        internal Guid DurableCreateGuid { get; }

        internal void MarkClosed()
        {
            IsClosed = true;
        }

        internal void InvalidateDurableReconnect()
        {
            CanReconnectDurably = false;
        }

        internal void SetDeletePending(bool deletePending)
        {
            IsDeletePending = deletePending;
        }

        internal void SetOplockLevel(Smb2OplockLevel oplockLevel)
        {
            OplockLevel = oplockLevel;
        }

        internal void SetLeaseState(Smb2LeaseState leaseState)
        {
            LeaseState = leaseState;
        }

        internal void UpdatePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            Path = path;
        }
    }
}
