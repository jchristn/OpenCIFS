namespace OpenCIFS.Server
{
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerNamedPipeCreateOperationContext
    {
        public OpenCifsServerHost OwnerHost { get; set; } = null!;

        public ServerSessionRecord SessionRecord { get; set; } = null!;

        public ServerTreeRecord TreeRecord { get; set; } = null!;

        public Smb2CreateRequest Request { get; set; } = null!;

        public IReadOnlyList<Smb2CreateContext> CreateContexts { get; set; } = null!;
    }
}
