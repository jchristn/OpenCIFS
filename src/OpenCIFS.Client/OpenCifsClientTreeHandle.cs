namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Tree handle returned by the managed direct-TCP client connection surface.
    /// </summary>
    public sealed class OpenCifsClientTreeHandle
    {
        /// <summary>
        /// Initialize a tracked tree handle.
        /// </summary>
        /// <param name="connectionId">Owning connection identifier.</param>
        /// <param name="sessionGeneration">Owning session generation.</param>
        /// <param name="shareName">Connected share name.</param>
        /// <param name="treeId">Server-assigned tree identifier.</param>
        /// <param name="shareFlags">Tree-connect share flags returned by the server.</param>
        internal OpenCifsClientTreeHandle(Guid connectionId, long sessionGeneration, string shareName, uint treeId, Smb2ShareFlags shareFlags)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            ConnectionId = connectionId;
            SessionGeneration = sessionGeneration;
            ShareName = shareName;
            TreeId = treeId;
            ShareFlags = shareFlags;
        }

        /// <summary>
        /// Connected share name.
        /// </summary>
        public string ShareName { get; }

        /// <summary>
        /// Server-assigned tree identifier.
        /// </summary>
        public uint TreeId { get; }

        /// <summary>
        /// Tree-connect share flags returned by the server.
        /// </summary>
        public Smb2ShareFlags ShareFlags { get; }

        /// <summary>
        /// Whether the share participates in DFS.
        /// </summary>
        public bool IsDfs
        {
            get
            {
                return (ShareFlags & Smb2ShareFlags.Dfs) != 0;
            }
        }

        /// <summary>
        /// Whether the share is a DFS root.
        /// </summary>
        public bool IsDfsRoot
        {
            get
            {
                return (ShareFlags & Smb2ShareFlags.DfsRoot) != 0;
            }
        }

        /// <summary>
        /// Whether this tree handle has been disconnected and can no longer be used.
        /// </summary>
        public bool IsDisconnected { get; private set; }

        internal Guid ConnectionId { get; }

        internal long SessionGeneration { get; }

        internal void MarkDisconnected()
        {
            IsDisconnected = true;
        }
    }
}
