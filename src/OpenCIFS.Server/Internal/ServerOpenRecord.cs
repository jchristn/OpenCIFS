namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;

    internal sealed class ServerOpenRecord : IDisposable
    {
        public OpenCifsServerHost OwnerHost { get; set; } = null!;

        public ulong SessionId { get; set; }

        public uint TreeId { get; set; }

        public string ShareName { get; set; } = string.Empty;

        public string ShareRootPath { get; set; } = string.Empty;

        public OpenCifsServerShareBackend Backend { get; set; } = null!;

        public string FullPath { get; set; } = string.Empty;

        public uint DesiredAccess { get; set; }

        public uint ShareAccess { get; set; }

        public bool CanRead { get; set; }

        public bool CanWrite { get; set; }

        public bool CanReadData { get; set; }

        public bool CanWriteData { get; set; }

        public bool CanDelete { get; set; }

        public bool IsDirectory { get; set; }

        public bool IsNamedPipeEndpoint { get; set; }

        public OpenCifsServerNamedPipeEndpoint? NamedPipeEndpoint { get; set; }

        public Smb2OplockLevel GrantedOplockLevel { get; set; } = Smb2OplockLevel.None;

        public Smb2OplockLevel PendingOplockBreakLevel { get; set; } = Smb2OplockLevel.None;

        public bool IsOplockBreakInProgress { get; set; }

        public OpenCifsServerLeaseRecord? LeaseRecord { get; set; }

        public string? DirectoryEnumerationPattern { get; set; }

        public int DirectoryEnumerationIndex { get; set; }

        public List<ServerByteRangeLock> Locks { get; } = new List<ServerByteRangeLock>();

        public FileStream? Stream { get; set; }

        public OpenState State { get; set; } = null!;

        public bool SuppressAccessTimeUpdates { get; set; }

        public bool SuppressModificationTimeUpdates { get; set; }

        public bool SuppressChangeTimeUpdates { get; set; }

        public void Dispose()
        {
            Stream?.Dispose();
            State.Dispose();
        }
    }
}
