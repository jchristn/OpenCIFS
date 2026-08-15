namespace OpenCIFS.Server.Tests.Shared
{
    internal sealed class AuthenticatedTreeContext
    {
        public AuthenticatedTreeContext(ulong sessionId, uint treeId)
        {
            SessionId = sessionId;
            TreeId = treeId;
        }

        public ulong SessionId { get; }

        public uint TreeId { get; }
    }
}
