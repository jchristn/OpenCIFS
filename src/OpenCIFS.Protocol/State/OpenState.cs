namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Tracks SMB file open lifecycle state.
    /// </summary>
    public sealed class OpenState : DisposableStateBase
    {
        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; private set; } = 0;

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; private set; } = 0;

        /// <summary>
        /// Opened path.
        /// </summary>
        public string Path
        {
            get
            {
                return _Path;
            }
            private set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(Path), "Path cannot be null or whitespace.");
                }

                _Path = value;
            }
        }

        /// <summary>
        /// Whether delete-pending has been set.
        /// </summary>
        public bool IsDeletePending { get; private set; } = false;

        /// <summary>
        /// Currently tracked oplock level for the open.
        /// </summary>
        public Smb2OplockLevel OplockLevel { get; private set; } = Smb2OplockLevel.None;

        /// <summary>
        /// Whether the open can be re-established as a durable handle.
        /// </summary>
        public bool IsDurable { get; private set; } = false;

        /// <summary>
        /// Lease key bytes when the open is backed by an SMB 2.1 lease.
        /// </summary>
        public byte[] LeaseKey
        {
            get
            {
                return _LeaseKey;
            }
            private set
            {
                _LeaseKey = value ?? throw new ArgumentNullException(nameof(LeaseKey), "LeaseKey cannot be null.");
            }
        }

        /// <summary>
        /// Current SMB 2.1 lease state for the open.
        /// </summary>
        public Smb2LeaseState LeaseState { get; private set; } = Smb2LeaseState.None;

        /// <summary>
        /// Bind the open state to a file identifier pair.
        /// </summary>
        /// <param name="persistentFileId">Persistent file identifier.</param>
        /// <param name="volatileFileId">Volatile file identifier.</param>
        /// <param name="path">Opened path.</param>
        public void Bind(ulong persistentFileId, ulong volatileFileId, string path)
        {
            EnsureNotDisposed();

            if (persistentFileId == 0 && volatileFileId == 0)
            {
                throw new ArgumentException("At least one file identifier must be non-zero.", nameof(persistentFileId));
            }

            PersistentFileId = persistentFileId;
            VolatileFileId = volatileFileId;
            Path = path;
        }

        /// <summary>
        /// Mark the open as delete-pending.
        /// </summary>
        public void MarkDeletePending()
        {
            EnsureNotDisposed();
            IsDeletePending = true;
        }

        /// <summary>
        /// Set whether the open is delete-pending.
        /// </summary>
        /// <param name="deletePending">Delete-pending state.</param>
        public void SetDeletePending(bool deletePending)
        {
            EnsureNotDisposed();
            IsDeletePending = deletePending;
        }

        /// <summary>
        /// Update the tracked oplock level for the open.
        /// </summary>
        /// <param name="oplockLevel">Applied oplock level.</param>
        public void SetOplockLevel(Smb2OplockLevel oplockLevel)
        {
            EnsureNotDisposed();
            OplockLevel = oplockLevel;
        }

        /// <summary>
        /// Update whether the open is durable.
        /// </summary>
        /// <param name="isDurable">Durable state.</param>
        public void SetDurable(bool isDurable)
        {
            EnsureNotDisposed();
            IsDurable = isDurable;
        }

        /// <summary>
        /// Apply an SMB 2.1 lease key and state to the open.
        /// </summary>
        /// <param name="leaseKey">Lease key bytes.</param>
        /// <param name="leaseState">Lease state.</param>
        public void SetLease(byte[] leaseKey, Smb2LeaseState leaseState)
        {
            EnsureNotDisposed();

            if (leaseKey == null)
            {
                throw new ArgumentNullException(nameof(leaseKey), "LeaseKey cannot be null.");
            }

            if (leaseKey.Length != 16)
            {
                throw new ArgumentException("The SMB 2.1 lease key must be 16 bytes long.", nameof(leaseKey));
            }

            LeaseKey = (byte[])leaseKey.Clone();
            LeaseState = leaseState;
        }

        /// <summary>
        /// Clear the SMB 2.1 lease state tracked for the open.
        /// </summary>
        public void ClearLease()
        {
            EnsureNotDisposed();
            LeaseKey = Array.Empty<byte>();
            LeaseState = Smb2LeaseState.None;
        }

        /// <summary>
        /// Update the SMB 2.1 lease state tracked for the open.
        /// </summary>
        /// <param name="leaseState">Lease state.</param>
        public void SetLeaseState(Smb2LeaseState leaseState)
        {
            EnsureNotDisposed();
            LeaseState = leaseState;
        }

        /// <summary>
        /// Update the tracked path for the open.
        /// </summary>
        /// <param name="path">New relative path.</param>
        public void UpdatePath(string path)
        {
            EnsureNotDisposed();
            Path = path;
        }

        private string _Path = String.Empty;
        private byte[] _LeaseKey = Array.Empty<byte>();
    }
}
