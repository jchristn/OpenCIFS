namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Detached durable-open state preserved across a direct-TCP connection loss.
    /// </summary>
    internal sealed class OpenCifsServerDurableOpenRecord : IDisposable
    {
        public ulong PersistentFileId { get; set; }

        public string DurableOwnerUserName { get; set; } = string.Empty;

        public string DurableOwnerUserDomain { get; set; } = string.Empty;

        public string ShareName { get; set; } = string.Empty;

        public string ShareRootPath { get; set; } = string.Empty;

        public OpenCifsServerShareBackend Backend { get; set; } = null!;

        public string FullPath { get; set; } = string.Empty;

        public string RelativePath { get; set; } = string.Empty;

        public uint DesiredAccess { get; set; }

        public uint ShareAccess { get; set; }

        public bool CanRead { get; set; }

        public bool CanWrite { get; set; }

        public bool CanReadData { get; set; }

        public bool CanWriteData { get; set; }

        public bool CanDelete { get; set; }

        public Smb2OplockLevel GrantedOplockLevel { get; set; } = Smb2OplockLevel.None;

        public bool IsDeletePending { get; set; }

        public bool SuppressAccessTimeUpdates { get; set; }

        public bool SuppressModificationTimeUpdates { get; set; }

        public bool SuppressChangeTimeUpdates { get; set; }

        public List<OpenCifsServerDetachedByteRangeLock> Locks { get; } = new List<OpenCifsServerDetachedByteRangeLock>();

        public FileStream? Stream { get; set; }

        public void Dispose()
        {
            Stream?.Dispose();
        }
    }
}
