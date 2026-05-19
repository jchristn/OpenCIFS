namespace OpenCIFS.Server
{
    using System;

    internal sealed class DfsReferralMatch
    {
        public string ServerName { get; set; } = string.Empty;

        public string ShareName { get; set; } = string.Empty;

        public string NamespacePath { get; set; } = string.Empty;

        public OpenCifsServerDfsReferral[] Referrals { get; set; } = Array.Empty<OpenCifsServerDfsReferral>();
    }
}
