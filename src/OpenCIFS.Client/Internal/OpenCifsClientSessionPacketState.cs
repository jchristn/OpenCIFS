namespace OpenCIFS.Client
{
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientSessionPacketState
    {
        public OpenCifsClientSessionPacketState()
        {
            ConnectionState = new ConnectionState();
            AvailableMessageIds = new Queue<ulong>();
            PendingRequests = new Dictionary<ulong, RequestState>();
            NextMessageIdToGrant = 1;
        }

        public Queue<ulong> AvailableMessageIds { get; }

        public ConnectionState ConnectionState { get; }

        public ulong NextMessageIdToGrant { get; set; }

        public IDictionary<ulong, RequestState> PendingRequests { get; }
    }
}
