namespace OpenCIFS.Server
{
    internal sealed class RegisteredShareRecord
    {
        public string ShareName { get; set; } = string.Empty;

        public string RootPath { get; set; } = string.Empty;

        public OpenCifsServerShareBackend Backend { get; set; } = null!;

        public bool IsNamedPipeShare { get; set; }
    }
}
