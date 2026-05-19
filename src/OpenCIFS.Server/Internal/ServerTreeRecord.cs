namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    internal sealed class ServerTreeRecord
    {
        public TreeConnectState State { get; } = new TreeConnectState();

        public string ShareName { get; set; } = string.Empty;

        public string ShareRootPath { get; set; } = string.Empty;

        public OpenCifsServerShareBackend Backend { get; set; } = null!;

        public bool IsNamedPipeShare { get; set; }
    }
}
