namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;

    internal sealed class InitialSessionSetupToken
    {
        public SessionSetupFlavor Flavor { get; set; }

        public SpnegoNegTokenInit? SpnegoInitToken { get; set; }

        public OpenCifsNtlmNegotiateToken? LegacyNegotiateToken { get; set; }

        public NtlmNegotiateMessage? StandardNegotiateMessage { get; set; }

        public byte[]? StandardNegotiateMessageBytes { get; set; }

        public string? SelectedMechanismOid { get; set; }
    }
}
