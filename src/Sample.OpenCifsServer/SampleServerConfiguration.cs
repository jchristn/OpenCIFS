namespace Sample.OpenCifsServer
{
    using System;
    using System.IO;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;

    /// <summary>
    /// Configuration model for the executable sample server host.
    /// </summary>
    public sealed class SampleServerConfiguration
    {
        /// <summary>
        /// Server display name.
        /// </summary>
        public string ServerName { get; set; } = "OpenCIFS";

        /// <summary>
        /// Local bind address.
        /// </summary>
        public string BindAddress { get; set; } = "127.0.0.1";

        /// <summary>
        /// Local bind port.
        /// </summary>
        public int BindPort { get; set; } = 4450;

        /// <summary>
        /// Share name exposed by the sample host.
        /// </summary>
        public string ShareName { get; set; } = "share";

        /// <summary>
        /// Filesystem path for the sample share.
        /// </summary>
        public string SharePath { get; set; } = "SampleShare";

        /// <summary>
        /// Minimum negotiated dialect.
        /// </summary>
        public SmbDialect MinimumDialect { get; set; } = SmbDialect.Smb2002;

        /// <summary>
        /// Maximum negotiated dialect.
        /// </summary>
        public SmbDialect MaximumDialect { get; set; } = SmbDialect.Smb311;

        /// <summary>
        /// Whether signing is required.
        /// </summary>
        public bool RequireSigning { get; set; } = true;

        /// <summary>
        /// Whether NTLMv2 is required.
        /// </summary>
        public bool RequireNtlmV2 { get; set; } = true;

        /// <summary>
        /// Whether anonymous access is allowed.
        /// </summary>
        public bool AllowAnonymous { get; set; } = false;

        /// <summary>
        /// Whether SMB1 is enabled.
        /// </summary>
        public bool EnableSmb1 { get; set; } = false;

        /// <summary>
        /// Whether SMB 3.x sessions require encryption when the dialect supports it.
        /// </summary>
        public bool RequireEncryptionForSmb3 { get; set; } = true;

        /// <summary>
        /// Whether the bounded SMB 3.1.1 preview slice should be enabled on the sample server.
        /// </summary>
        public bool EnableSmb311Preview { get; set; } = false;

        /// <summary>
        /// Test account user name.
        /// </summary>
        public string AccountUserName { get; set; } = "alice";

        /// <summary>
        /// Test account domain.
        /// </summary>
        public string AccountUserDomain { get; set; } = "WORKGROUP";

        /// <summary>
        /// Test account password.
        /// </summary>
        public string AccountPassword { get; set; } = "Password123!";

        /// <summary>
        /// Apply command-line overrides to this configuration and return the effective configuration.
        /// </summary>
        /// <param name="options">Parsed command-line overrides.</param>
        /// <returns>Effective configuration.</returns>
        public SampleServerConfiguration ApplyCommandLineOptions(SampleServerCommandLineOptions options)
        {
            return new SampleServerConfiguration
            {
                ServerName = options.ServerName ?? ServerName,
                BindAddress = options.BindAddress ?? BindAddress,
                BindPort = options.BindPort ?? BindPort,
                ShareName = options.ShareName ?? ShareName,
                SharePath = options.SharePath ?? SharePath,
                MinimumDialect = options.MinimumDialect ?? MinimumDialect,
                MaximumDialect = options.MaximumDialect ?? MaximumDialect,
                RequireSigning = options.RequireSigning ?? RequireSigning,
                RequireNtlmV2 = options.RequireNtlmV2 ?? RequireNtlmV2,
                AllowAnonymous = options.AllowAnonymous ?? AllowAnonymous,
                EnableSmb1 = options.EnableSmb1 ?? EnableSmb1,
                RequireEncryptionForSmb3 = options.RequireEncryptionForSmb3 ?? RequireEncryptionForSmb3,
                EnableSmb311Preview = options.EnableSmb311Preview ?? EnableSmb311Preview,
                AccountUserName = options.AccountUserName ?? AccountUserName,
                AccountUserDomain = options.AccountUserDomain ?? AccountUserDomain,
                AccountPassword = options.AccountPassword ?? AccountPassword
            };
        }

        /// <summary>
        /// Convert the sample configuration into server options.
        /// </summary>
        /// <param name="configurationPath">Resolved configuration file path.</param>
        /// <returns>Server options for the sample host.</returns>
        public OpenCifsServerOptions ToServerOptions(string configurationPath)
        {
            string configurationDirectory = Path.GetDirectoryName(Path.GetFullPath(configurationPath)) ?? Environment.CurrentDirectory;
            string resolvedSharePath = SharePath;

            if (!Path.IsPathRooted(resolvedSharePath))
            {
                resolvedSharePath = Path.GetFullPath(Path.Combine(configurationDirectory, resolvedSharePath));
            }

            OpenCifsServerOptions options = new OpenCifsServerOptions
            {
                ServerName = ServerName,
                BindAddress = BindAddress,
                BindPort = BindPort,
                ShareName = ShareName,
                SharePath = resolvedSharePath,
                MinimumDialect = MinimumDialect,
                MaximumDialect = MaximumDialect,
                RequireSigning = RequireSigning,
                RequireNtlmV2 = RequireNtlmV2,
                AllowAnonymous = AllowAnonymous,
                EnableSmb1 = EnableSmb1,
                RequireEncryptionForSmb3 = RequireEncryptionForSmb3,
                EnableSmb311Preview = EnableSmb311Preview
            };

            options.Validate();
            return options;
        }

        /// <summary>
        /// Convert the sample account fields into a registered server account.
        /// </summary>
        /// <returns>Server account.</returns>
        public OpenCifsServerAccount ToServerAccount()
        {
            return new OpenCifsServerAccount
            {
                UserName = AccountUserName,
                UserDomain = AccountUserDomain,
                Password = AccountPassword
            };
        }
    }
}
