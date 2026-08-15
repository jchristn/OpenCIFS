namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Sample.OpenCifsServer;
    using Touchstone.Core;
    using static OpenCIFS.Server.Tests.Shared.ServerTestSupport;
    internal static class ServerDefaultsSampleProgramCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleConfigurationExists",
                        displayName: "Sample configuration file exists",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string path = RepositoryPaths.FromRoot(Path.Combine("src", "Sample.OpenCifsServer", "sample.opencifs.server.json"));
                            FileAssertions.AssertExists(path);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleConfigurationDefaultsRemainSecure",
                        displayName: "Sample configuration defaults remain secure and match the planned tester posture",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SampleServerConfiguration configuration = new SampleServerConfiguration();
                            OpenCifsServerOptions options = configuration.ToServerOptions(Path.Combine(Path.GetTempPath(), "sample.opencifs.server.json"));

                            if (options.BindPort != 4450)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to default to bind port 4450.");
                            }

                            if (!options.RequireSigning || !options.RequireNtlmV2)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to require signing and NTLMv2.");
                            }

                            if (options.AllowAnonymous || options.EnableSmb1)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to disable anonymous access and SMB1.");
                            }

                            if (!options.RequireEncryptionForSmb3)
                            {
                                throw new InvalidOperationException("Expected the sample configuration to require SMB 3.x encryption.");
                            }

                            if (configuration.AccountUserName != "alice" || configuration.AccountUserDomain != "WORKGROUP")
                            {
                                throw new InvalidOperationException("Expected the sample configuration to expose the documented test credentials.");
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleProgramWritesValidatesAndPrintsGuidanceWithOverrides",
                        displayName: "Sample program writes defaults, validates overrides, and prints deterministic tester guidance",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = Path.Combine(Path.GetTempPath(), "OpenCifsSampleProgram_" + Guid.NewGuid().ToString("N"));
                            string configurationPath = Path.Combine(rootPath, "config", "sample.opencifs.server.json");

                            Directory.CreateDirectory(rootPath);

                            try
                            {
                                SampleProgramExecutionResult writeResult = RunSampleProgram(
                                    "--config", configurationPath,
                                    "--write-default-config");

                                int writeExitCode = writeResult.ExitCode;

                                string writeOutput = writeResult.StandardOutput;

                                string writeError = writeResult.StandardError;

                                if (writeExitCode != 0)
                                {
                                    throw new InvalidOperationException("Expected the sample program to write the default configuration. Error: " + writeError);
                                }

                                FileAssertions.AssertExists(configurationPath);

                                if (!writeOutput.Contains(Path.GetFullPath(configurationPath), StringComparison.Ordinal))
                                {
                                    throw new InvalidOperationException("Expected the sample program to report the full configuration path after writing defaults.");
                                }

                                string expectedResolvedSharePath = Path.GetFullPath(Path.Combine(Path.GetDirectoryName(configurationPath)!, "Shares", "Public"));

                                SampleProgramExecutionResult validateResult = RunSampleProgram(
                                    "--config", configurationPath,
                                    "--validate-config",
                                    "--server-name", "fileserver",
                                    "--bind-address", "0.0.0.0",
                                    "--bind-port", "445",
                                    "--share-name", "public",
                                    "--share-path", Path.Combine("Shares", "Public"),
                                    "--account-username", "bob",
                                    "--account-domain", "LAB",
                                    "--account-password", "Secret123!",
                                    "--minimum-dialect", "Smb2002",
                                    "--maximum-dialect", "Smb311");


                                int validateExitCode = validateResult.ExitCode;


                                string validateOutput = validateResult.StandardOutput;


                                string validateError = validateResult.StandardError;

                                if (validateExitCode != 0)
                                {
                                    throw new InvalidOperationException("Expected the sample program to validate the effective configuration. Error: " + validateError);
                                }

                                if (!validateOutput.Contains("Bind endpoint: 0.0.0.0:445", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Share path: " + expectedResolvedSharePath, StringComparison.Ordinal) ||
                                    !validateOutput.Contains("UNC path: \\\\fileserver\\public", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Native Windows mount target: \\\\fileserver\\public", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Account password: <redacted>", StringComparison.Ordinal) ||
                                    !validateOutput.Contains("Validation: OK", StringComparison.Ordinal))
                                {
                                    throw new InvalidOperationException("Expected the validation report to include deterministic connection guidance and a redacted credential summary.");
                                }

                                SampleProgramExecutionResult printResult = RunSampleProgram(
                                    "--config", configurationPath,
                                    "--print-config",
                                    "--server-name", "127.0.0.1",
                                    "--bind-address", "127.0.0.1",
                                    "--bind-port", "4450",
                                    "--share-name", "share",
                                    "--share-path", "SampleShare");


                                int printExitCode = printResult.ExitCode;


                                string printOutput = printResult.StandardOutput;


                                string printError = printResult.StandardError;

                                if (printExitCode != 0)
                                {
                                    throw new InvalidOperationException("Expected the sample program to print the effective configuration. Error: " + printError);
                                }

                                if (!printOutput.Contains("Direct-TCP endpoint: 127.0.0.1:4450", StringComparison.Ordinal) ||
                                    !printOutput.Contains("Native Windows mount note: Windows Explorer and net use require port 445;", StringComparison.Ordinal))
                                {
                                    throw new InvalidOperationException("Expected the configuration report to explain how custom ports affect native Windows mounting.");
                                }
                            }
                            finally
                            {
                                DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Server.Defaults",
                        caseId: "SampleProgramRejectsConflictingModesAndInvalidOverrides",
                        displayName: "Sample program rejects conflicting modes and invalid override values",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SampleProgramExecutionResult conflictingResult = RunSampleProgram(
                                "--print-config",
                                "--validate-config");

                            int conflictingExitCode = conflictingResult.ExitCode;

                            string conflictingError = conflictingResult.StandardError;

                            if (conflictingExitCode == 0 || !conflictingError.Contains("Specify at most one of --write-default-config, --print-config, or --validate-config.", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the sample program to reject conflicting command modes.");
                            }

                            SampleProgramExecutionResult invalidResult = RunSampleProgram(
                                "--bind-port", "not-a-number");

                            int invalidExitCode = invalidResult.ExitCode;

                            string invalidError = invalidResult.StandardError;

                            if (invalidExitCode == 0 || !invalidError.Contains("Invalid integer value for --bind-port: not-a-number.", StringComparison.Ordinal))
                            {
                                throw new InvalidOperationException("Expected the sample program to reject invalid override values.");
                            }

                            return Task.CompletedTask;
                        }),
            };
        }
    }
}
