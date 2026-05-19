namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerRegularCreateOperationContext
    {
        public OpenCifsServerHost OwnerHost { get; set; } = null!;

        public ulong SessionId { get; set; }

        public uint TreeId { get; set; }

        public ServerSessionRecord SessionRecord { get; set; } = null!;

        public ServerTreeRecord TreeRecord { get; set; } = null!;

        public Smb2CreateRequest Request { get; set; } = null!;

        public string FullPath { get; set; } = string.Empty;

        public bool IsShareRootOpenRequest { get; set; }

        public bool DurableHandleRequested { get; set; }

        public Smb2DurableHandleRequestV2Context? DurableHandleRequestV2Context { get; set; }

        public Smb2CreateRequestLeaseContext? LeaseRequestContext { get; set; }

        public SmbDialect? NegotiatedDialect { get; set; }

        public Guid NegotiatedClientGuid { get; set; }
    }
}
