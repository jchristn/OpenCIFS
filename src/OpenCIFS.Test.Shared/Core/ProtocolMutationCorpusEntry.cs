namespace OpenCIFS.Core.Tests.Shared
{
    using System;

    internal sealed class ProtocolMutationCorpusEntry
    {
        public ProtocolMutationCorpusEntry(string name, byte[] baseline, Action<byte[]> parser)
        {
            Name = name ?? throw new ArgumentNullException(nameof(name));
            Baseline = baseline ?? throw new ArgumentNullException(nameof(baseline));
            Parser = parser ?? throw new ArgumentNullException(nameof(parser));
        }

        public string Name { get; }

        public byte[] Baseline { get; }

        public Action<byte[]> Parser { get; }
    }
}
