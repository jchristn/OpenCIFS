namespace Sample.OpenCifsServer
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Server;

    /// <summary>
    /// Formats tester-facing console output for the sample server utility.
    /// </summary>
    public static class SampleServerConsoleFormatter
    {
        /// <summary>
        /// Create the configuration report text.
        /// </summary>
        /// <param name="configurationPath">Configuration file path.</param>
        /// <param name="configuration">Effective sample configuration.</param>
        /// <param name="options">Resolved server options.</param>
        /// <returns>Formatted report.</returns>
        public static string CreateConfigurationReport(string configurationPath, SampleServerConfiguration configuration, OpenCifsServerOptions options)
        {
            List<string> lines = new List<string>
            {
                "OpenCIFS sample server configuration",
                "Configuration file: " + configurationPath,
                "Server name: " + options.ServerName,
                "Bind endpoint: " + options.BindAddress + ":" + options.BindPort,
                "Share name: " + options.ShareName,
                "Share path: " + options.SharePath,
                "Account: " + configuration.AccountUserDomain + "\\" + configuration.AccountUserName,
                "Account password: <redacted>",
                "Signing required: " + options.RequireSigning,
                "NTLMv2 required: " + options.RequireNtlmV2,
                "Anonymous allowed: " + options.AllowAnonymous,
                "SMB1 enabled: " + options.EnableSmb1,
                "SMB 3.x encryption required: " + options.RequireEncryptionForSmb3,
                "SMB 3.1.1 preview enabled: " + options.EnableSmb311Preview,
                "Dialect range: " + options.MinimumDialect + " -> " + options.MaximumDialect,
                "UNC path: \\\\" + options.ServerName + "\\" + options.ShareName,
                "Direct-TCP endpoint: " + options.BindAddress + ":" + options.BindPort
            };

            AppendWindowsMountGuidance(lines, options);
            lines.Add("No SMB dialect is advertised by this sample host yet.");

            return String.Join(Environment.NewLine, lines);
        }

        /// <summary>
        /// Create the configuration validation report text.
        /// </summary>
        /// <param name="configurationPath">Configuration file path.</param>
        /// <param name="configuration">Effective sample configuration.</param>
        /// <param name="options">Resolved server options.</param>
        /// <returns>Formatted validation report.</returns>
        public static string CreateValidationReport(string configurationPath, SampleServerConfiguration configuration, OpenCifsServerOptions options)
        {
            return CreateConfigurationReport(configurationPath, configuration, options) + Environment.NewLine + "Validation: OK";
        }

        /// <summary>
        /// Create the startup banner text.
        /// </summary>
        /// <param name="configurationPath">Configuration file path.</param>
        /// <param name="configuration">Effective sample configuration.</param>
        /// <param name="options">Resolved server options.</param>
        /// <returns>Formatted startup banner.</returns>
        public static string CreateStartupBanner(string configurationPath, SampleServerConfiguration configuration, OpenCifsServerOptions options)
        {
            List<string> lines = new List<string>
            {
                "OpenCIFS sample server",
                "Configuration file: " + configurationPath,
                "Listening on " + options.BindAddress + ":" + options.BindPort + ".",
                "Share root: " + options.SharePath,
                "Connect as: " + configuration.AccountUserDomain + "\\" + configuration.AccountUserName,
                "UNC path: \\\\" + options.ServerName + "\\" + options.ShareName,
                "Direct-TCP endpoint: " + options.BindAddress + ":" + options.BindPort,
                "Security defaults: signing required=" + options.RequireSigning + ", NTLMv2 required=" + options.RequireNtlmV2 + ", anonymous allowed=" + options.AllowAnonymous + ", SMB1 enabled=" + options.EnableSmb1 + ", SMB 3.x encryption required=" + options.RequireEncryptionForSmb3 + ", SMB 3.1.1 preview enabled=" + options.EnableSmb311Preview + ".",
                "Dialect range: " + options.MinimumDialect + " -> " + options.MaximumDialect
            };

            AppendWindowsMountGuidance(lines, options);
            lines.Add("No SMB dialect is advertised by this sample host yet.");
            lines.Add("Press Ctrl+C to stop.");

            return String.Join(Environment.NewLine, lines);
        }

        private static void AppendWindowsMountGuidance(List<string> lines, OpenCifsServerOptions options)
        {
            if (options.BindPort == 445)
            {
                lines.Add("Native Windows mount target: \\\\" + options.ServerName + "\\" + options.ShareName);
                return;
            }

            lines.Add("Native Windows mount note: Windows Explorer and net use require port 445; bind to 445 or configure a local port forward because UNC paths do not encode custom ports.");
        }
    }
}
