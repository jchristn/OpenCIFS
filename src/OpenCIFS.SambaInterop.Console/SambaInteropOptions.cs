namespace OpenCIFS.SambaInterop.Console
{
    using OpenCIFS.Protocol;

    internal sealed class SambaInteropOptions
    {
        public SmbDialect Dialect { get; init; }

        public string Domain { get; init; } = string.Empty;

        public int LargePayloadLength { get; init; } = 200000;

        public string OutputPath { get; init; } = string.Empty;

        public string Password { get; init; } = string.Empty;

        public int Port { get; init; }

        public string Server { get; init; } = string.Empty;

        public string Share { get; init; } = string.Empty;

        public string UserName { get; init; } = string.Empty;
    }
}
