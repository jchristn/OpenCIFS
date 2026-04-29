namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Tracks SMB tree connect lifecycle state.
    /// </summary>
    public sealed class TreeConnectState : DisposableStateBase
    {
        /// <summary>
        /// Tree identifier.
        /// </summary>
        public uint TreeId { get; private set; } = 0;

        /// <summary>
        /// Share name.
        /// </summary>
        public string ShareName
        {
            get
            {
                return _ShareName;
            }
            private set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(ShareName), "ShareName cannot be null or whitespace.");
                }

                _ShareName = value;
            }
        }

        /// <summary>
        /// Whether the tree is connected.
        /// </summary>
        public bool IsConnected { get; private set; } = false;

        /// <summary>
        /// Mark the tree as connected.
        /// </summary>
        /// <param name="treeId">Tree identifier.</param>
        /// <param name="shareName">Share name.</param>
        public void Connect(uint treeId, string shareName)
        {
            EnsureNotDisposed();

            if (treeId == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(treeId), "Tree identifiers must be non-zero.");
            }

            TreeId = treeId;
            ShareName = shareName;
            IsConnected = true;
        }

        /// <summary>
        /// Mark the tree as disconnected.
        /// </summary>
        public void Disconnect()
        {
            EnsureNotDisposed();
            IsConnected = false;
        }

        private string _ShareName = String.Empty;
    }
}

