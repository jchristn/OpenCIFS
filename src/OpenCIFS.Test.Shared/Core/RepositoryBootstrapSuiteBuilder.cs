namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class RepositoryBootstrapSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Bootstrap",
                displayName: "Core bootstrap artifacts",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "RequiredArtifactsExist",
                        displayName: "Required repository artifacts exist",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string repositoryRoot = RepositoryPaths.GetRepositoryRoot();
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "README.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "CHANGELOG.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "LICENSE.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "docs", "coverage-matrix.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "docs", "interop-matrix.md"));
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "CoverageMatrixTemplatePresent",
                        displayName: "Coverage matrix template includes required headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string coverageMatrixPath = RepositoryPaths.FromRoot(Path.Combine("docs", "coverage-matrix.md"));
                            FileAssertions.AssertContains(coverageMatrixPath, "| dialect | area | command or capability |");
                            FileAssertions.AssertContains(coverageMatrixPath, "| SMB 3.1.1 | negotiate contexts |");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "FileAssertionsRejectMissingArtifactsAndHeaders",
                        displayName: "Bootstrap file assertions reject missing artifacts and headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string tempDirectory = TestPathUtilities.CreateUniqueDirectory("OpenCifsBootstrapAssertions_");

                            try
                            {
                                string missingFilePath = Path.Combine(tempDirectory, "missing.md");
                                string coverageMatrixPath = Path.Combine(tempDirectory, "coverage-matrix.md");
                                File.WriteAllText(coverageMatrixPath, "| dialect | area | command or capability |");

                                TestAssertions.Throws<FileNotFoundException>(
                                    () => FileAssertions.AssertExists(missingFilePath),
                                    "Expected bootstrap file assertions to reject missing repository artifacts.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => FileAssertions.AssertContains(coverageMatrixPath, "| SMB 3.1.1 | negotiate contexts |"),
                                    "Expected bootstrap file assertions to reject incomplete coverage matrix content.");
                            }
                            finally
                            {
                                TestPathUtilities.DeleteDirectoryForcefully(tempDirectory);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "SharedTestUtilitiesExposeDeterministicRootsVectorsAndPacketTraces",
                        displayName: "Shared test utilities expose deterministic roots, vectors, clocks, and packet traces",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = TestPathUtilities.CreateUniqueDirectory("OpenCifsSharedUtilities_");

                            try
                            {
                                TestAssertions.True(Directory.Exists(rootPath), "Expected the shared test path helper to create the requested directory.");
                                TestAssertions.Equal(
                                    DeterministicTestClock.GetUtc("Core.Bootstrap.UtilityClock"),
                                    DeterministicTestClock.GetUtc("Core.Bootstrap.UtilityClock"),
                                    "Expected the deterministic test clock to return the same timestamp for the same key.");
                                TestAssertions.SequenceEqual(
                                    Hex("31D6CFE0D16AE931B73C59D7E0C089C0"),
                                    GoldenVectorStore.GetBytes("core.security.md4.empty"),
                                    "Expected the golden-vector store to return the stored MD4 empty-string vector.");

                                PacketCaptureTraceWriter traceWriter = new PacketCaptureTraceWriter(rootPath, "CoreBootstrapUtilityTrace");
                                traceWriter.Capture("negotiate-request", new byte[] { 0x01, 0x02, 0x03 });
                                traceWriter.Capture("negotiate-response", new byte[] { 0x11, 0x12 });
                                string manifestPath = traceWriter.WriteManifest();

                                FileAssertions.AssertExists(manifestPath);
                                FileAssertions.AssertContains(manifestPath, "\"packet_count\": 2");
                                FileAssertions.AssertContains(manifestPath, "negotiate-request");
                                FileAssertions.AssertContains(manifestPath, "negotiate-response");
                            }
                            finally
                            {
                                TestPathUtilities.DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "SharedTestUtilitiesRejectInvalidArguments",
                        displayName: "Shared test utilities reject invalid arguments and missing vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = TestPathUtilities.CreateUniqueDirectory("OpenCifsSharedUtilitiesNegative_");

                            try
                            {
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => TestPathUtilities.CreateUniqueDirectory(" "),
                                    "Expected the shared test path helper to reject empty prefixes.");
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => DeterministicTestClock.GetUtc(" "),
                                    "Expected the deterministic clock helper to reject empty keys.");
                                TestAssertions.Throws<KeyNotFoundException>(
                                    () => GoldenVectorStore.GetString("core.security.missing.vector"),
                                    "Expected the golden-vector store to reject unknown vector names.");
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => new PacketCaptureTraceWriter(rootPath, " "),
                                    "Expected the packet-capture helper to reject empty trace names.");

                                PacketCaptureTraceWriter traceWriter = new PacketCaptureTraceWriter(rootPath, "NegativeTrace");
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => traceWriter.Capture(" ", new byte[] { 0x00 }),
                                    "Expected the packet-capture helper to reject empty capture labels.");
                            }
                            finally
                            {
                                TestPathUtilities.DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "CoreSuitesExposePositiveAndNegativeVariants",
                        displayName: "Core shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(CoreTestSuites.All, "Core");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
