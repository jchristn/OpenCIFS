namespace OpenCIFS.Server.Tests.Shared
{
    using System;

    internal sealed class DirectTcpMutationRequestBaseline
    {
        public DirectTcpMutationRequestBaseline(string name, byte[] payload)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Payload = payload ?? throw new ArgumentNullException(nameof(payload));
        }

        public string Name { get; }

        public byte[] Payload { get; }
    }
}
