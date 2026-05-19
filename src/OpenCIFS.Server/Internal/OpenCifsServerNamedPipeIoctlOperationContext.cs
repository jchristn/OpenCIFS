namespace OpenCIFS.Server
{
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerNamedPipeIoctlOperationContext
    {
        public ServerSessionRecord SessionRecord { get; set; } = null!;

        public uint TreeId { get; set; }

        public Smb2IoctlRequest Request { get; set; } = null!;

        public ServerOpenRecord? OpenRecord { get; set; }

        public SmbDialect? NegotiatedDialect { get; set; }

        public string ServerName { get; set; } = string.Empty;

        public IReadOnlyList<OpenCifsServerShareInfo> AvailableShares { get; set; } = null!;
    }
}
