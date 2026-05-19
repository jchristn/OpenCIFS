namespace OpenCIFS.Server
{
    internal sealed class ServerByteRangeLock
    {
        public ulong OwnerVolatileFileId { get; set; }

        public ulong Offset { get; set; }

        public ulong Length { get; set; }

        public bool IsShared { get; set; }

        public ulong EndOffset
        {
            get
            {
                return Offset + Length;
            }
        }
    }
}
