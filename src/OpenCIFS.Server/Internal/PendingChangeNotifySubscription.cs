namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    internal sealed class PendingChangeNotifySubscription
    {
        public ulong SequenceId { get; set; }

        public ulong MessageId { get; set; }

        public ulong SessionId { get; set; }

        public uint TreeId { get; set; }

        public ulong PersistentFileId { get; set; }

        public ulong VolatileFileId { get; set; }

        public string DirectoryFullPath { get; set; } = string.Empty;

        public bool WatchTree { get; set; }

        public FileNotifyChangeFilter CompletionFilter { get; set; } = FileNotifyChangeFilter.None;

        public uint OutputBufferLength { get; set; }
    }
}
