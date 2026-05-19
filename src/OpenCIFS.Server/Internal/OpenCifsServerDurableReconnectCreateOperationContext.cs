namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerDurableReconnectCreateOperationContext
    {
        public OpenCifsServerHost OwnerHost { get; set; } = null!;

        public ServerSessionRecord SessionRecord { get; set; } = null!;

        public ServerTreeRecord TreeRecord { get; set; } = null!;

        public Smb2CreateRequest Request { get; set; } = null!;

        public string FullPath { get; set; } = string.Empty;

        public ulong PersistentFileId { get; set; }

        public Guid? DurableCreateGuid { get; set; }

        public Smb2CreateRequestLeaseContext? LeaseRequestContext { get; set; }

        public Guid NegotiatedClientGuid { get; set; }
    }
}
