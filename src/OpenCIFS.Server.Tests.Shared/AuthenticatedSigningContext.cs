namespace OpenCIFS.Server.Tests.Shared
{
    using System;

    internal sealed class AuthenticatedSigningContext
    {
        public AuthenticatedSigningContext(ulong sessionId, byte[] signingKey)
        {
            SessionId = sessionId;
            SigningKey = signingKey ?? throw new ArgumentNullException(nameof(signingKey));
        }

        public ulong SessionId { get; }

        public byte[] SigningKey { get; }
    }
}
