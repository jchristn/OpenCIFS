namespace OpenCIFS.Client
{
    using OpenCIFS.Protocol;

    internal sealed class ClientOpenRecord
    {
        public uint TreeId { get; set; }

        public OpenState State { get; set; } = null!;
    }
}
