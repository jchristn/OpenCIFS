namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerIoctlOperationContext
    {
        public ServerSessionRecord SessionRecord { get; set; } = null!;

        public uint TreeId { get; set; }

        public Smb2IoctlRequest Request { get; set; } = null!;

        public ServerOpenRecord? OpenRecord { get; set; }

        public SmbDialect? NegotiatedDialect { get; set; }

        public Guid NegotiatedClientGuid { get; set; }

        public Smb2GlobalCapabilities NegotiatedClientCapabilities { get; set; }

        public Smb2SecurityMode NegotiatedClientSecurityMode { get; set; }

        public IReadOnlyList<SmbDialect> NegotiatedClientDialects { get; set; } = Array.Empty<SmbDialect>();

        public Smb2GlobalCapabilities NegotiatedServerCapabilities { get; set; }

        public Guid ServerGuid { get; set; }

        public Smb2SecurityMode NegotiatedServerSecurityMode { get; set; }

        public string ServerName { get; set; } = string.Empty;

        public IReadOnlyList<OpenCifsServerShareInfo> AvailableShares { get; set; } = Array.Empty<OpenCifsServerShareInfo>();
    }
}
