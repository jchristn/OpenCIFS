namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using OpenCIFS.Client;
    using OpenCIFS.Server;

    internal sealed class AuthenticatedLoopbackPair
    {
        public AuthenticatedLoopbackPair(OpenCifsServerHost host, OpenCifsClientSession client, ulong sessionId)
        {
            Host = host ?? throw new ArgumentNullException(nameof(host));
            Client = client ?? throw new ArgumentNullException(nameof(client));
            SessionId = sessionId;
        }

        public OpenCifsServerHost Host { get; }

        public OpenCifsClientSession Client { get; }

        public ulong SessionId { get; }
    }
}
