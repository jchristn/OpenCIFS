namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    internal sealed class RelatedCompoundContext
    {
        public ulong SessionId { get; private set; }

        public uint TreeId { get; private set; }

        public ulong PersistentFileId { get; private set; }

        public ulong VolatileFileId { get; private set; }

        public bool HasSessionId { get; private set; }

        public bool HasTreeId { get; private set; }

        public bool HasFileId { get; private set; }

        public bool PreviousCouldGenerateFileId { get; private set; }

        public NtStatus PreviousStatus { get; private set; } = NtStatus.Success;

        public void Update(NtStatus status, ulong sessionId, bool hasSessionId, uint treeId, bool hasTreeId, ulong persistentFileId, ulong volatileFileId, bool hasFileId, bool previousCouldGenerateFileId)
        {
            PreviousStatus = status;
            SessionId = sessionId;
            HasSessionId = hasSessionId;
            TreeId = treeId;
            HasTreeId = hasTreeId;
            PersistentFileId = persistentFileId;
            VolatileFileId = volatileFileId;
            HasFileId = hasFileId;
            PreviousCouldGenerateFileId = previousCouldGenerateFileId;
        }
    }
}
