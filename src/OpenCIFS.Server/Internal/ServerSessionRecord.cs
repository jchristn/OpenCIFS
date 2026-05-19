namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class ServerSessionRecord
    {
        public SessionState State { get; } = new SessionState();

        public Dictionary<uint, ServerTreeRecord> Trees { get; } = new Dictionary<uint, ServerTreeRecord>();

        public Dictionary<ulong, ServerOpenRecord> Opens { get; } = new Dictionary<ulong, ServerOpenRecord>();

        public string UserName { get; set; } = string.Empty;

        public string UserDomain { get; set; } = string.Empty;

        public byte[] ServerChallenge { get; set; } = Array.Empty<byte>();

        public SessionSetupFlavor SessionSetupFlavor { get; set; } = SessionSetupFlavor.LegacyOpenCifs;

        public string ExpectedServerName { get; set; } = string.Empty;

        public string ExpectedUserDomain { get; set; } = string.Empty;

        public byte[]? NegotiateMessage { get; set; }

        public byte[]? ChallengeMessage { get; set; }

        public byte[]? SessionBaseKey { get; set; }

        public byte[]? SessionKey { get; set; }

        public string[]? SpnegoMechanismTypes { get; set; }

        public byte[]? EncryptionKey { get; set; }

        public byte[]? DecryptionKey { get; set; }

        public bool EncryptData { get; set; }
    }
}
