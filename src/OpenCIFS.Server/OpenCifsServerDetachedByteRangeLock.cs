namespace OpenCIFS.Server
{
    /// <summary>
    /// Byte-range lock state preserved while a durable open is detached.
    /// </summary>
    internal sealed class OpenCifsServerDetachedByteRangeLock
    {
        public ulong Offset { get; set; }

        public ulong Length { get; set; }

        public bool IsShared { get; set; }
    }
}
