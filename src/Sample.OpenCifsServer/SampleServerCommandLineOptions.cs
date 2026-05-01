namespace Sample.OpenCifsServer
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Parsed command-line options for the sample server utility.
    /// </summary>
    public sealed class SampleServerCommandLineOptions
    {
        /// <summary>
        /// Configuration file path.
        /// </summary>
        public string ConfigurationPath { get; set; } = "sample.opencifs.server.json";

        /// <summary>
        /// Whether the default configuration should be written and the process should exit.
        /// </summary>
        public bool WriteDefaultConfiguration { get; set; }

        /// <summary>
        /// Whether the effective configuration should be printed and the process should exit.
        /// </summary>
        public bool PrintConfiguration { get; set; }

        /// <summary>
        /// Whether the effective configuration should be validated and the process should exit.
        /// </summary>
        public bool ValidateConfiguration { get; set; }

        /// <summary>
        /// Optional server-name override.
        /// </summary>
        public string? ServerName { get; set; }

        /// <summary>
        /// Optional bind-address override.
        /// </summary>
        public string? BindAddress { get; set; }

        /// <summary>
        /// Optional bind-port override.
        /// </summary>
        public int? BindPort { get; set; }

        /// <summary>
        /// Optional share-name override.
        /// </summary>
        public string? ShareName { get; set; }

        /// <summary>
        /// Optional share-path override.
        /// </summary>
        public string? SharePath { get; set; }

        /// <summary>
        /// Optional minimum-dialect override.
        /// </summary>
        public SmbDialect? MinimumDialect { get; set; }

        /// <summary>
        /// Optional maximum-dialect override.
        /// </summary>
        public SmbDialect? MaximumDialect { get; set; }

        /// <summary>
        /// Optional signing requirement override.
        /// </summary>
        public bool? RequireSigning { get; set; }

        /// <summary>
        /// Optional NTLMv2 requirement override.
        /// </summary>
        public bool? RequireNtlmV2 { get; set; }

        /// <summary>
        /// Optional anonymous-access override.
        /// </summary>
        public bool? AllowAnonymous { get; set; }

        /// <summary>
        /// Optional SMB1 enablement override.
        /// </summary>
        public bool? EnableSmb1 { get; set; }

        /// <summary>
        /// Optional SMB3 encryption requirement override.
        /// </summary>
        public bool? RequireEncryptionForSmb3 { get; set; }

        /// <summary>
        /// Optional bounded SMB 3.1.1 preview opt-in override.
        /// </summary>
        public bool? EnableSmb311Preview { get; set; }

        /// <summary>
        /// Optional account username override.
        /// </summary>
        public string? AccountUserName { get; set; }

        /// <summary>
        /// Optional account domain override.
        /// </summary>
        public string? AccountUserDomain { get; set; }

        /// <summary>
        /// Optional account password override.
        /// </summary>
        public string? AccountPassword { get; set; }
    }
}
