namespace OpenCIFS.Client
{
    using System;

    internal sealed class DfsReferralCacheEntry
    {
        public string ReferralPath { get; set; } = string.Empty;

        public DateTime ExpiresAtUtc { get; set; }

        public DateTime LastAccessUtc { get; set; }

        public OpenCifsDfsReferral[] Referrals { get; set; } = Array.Empty<OpenCifsDfsReferral>();
    }
}
