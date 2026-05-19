namespace OpenCIFS.Server
{
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal struct FileMetadata
    {
        public ulong CreationTime;

        public ulong LastAccessTime;

        public ulong LastWriteTime;

        public ulong ChangeTime;

        public ulong AllocationSize;

        public ulong EndOfFile;

        public ProtocolFileAttributes FileAttributes;
    }
}
