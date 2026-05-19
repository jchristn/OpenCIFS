namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class InteropBootstrapArtifactsSuiteBuilder
    {
        internal static TestSuiteDescriptor InteropArtifactsSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Interop.Bootstrap",
                displayName: "Interop bootstrap artifacts",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Interop.Bootstrap",
                        caseId: "InteropMatrixIncludesWindowsAndSamba",
                        displayName: "Interop matrix includes Windows and Samba targets",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string interopMatrixPath = RepositoryPaths.FromRoot(Path.Combine("docs", "interop-matrix.md"));
                            FileAssertions.AssertContains(interopMatrixPath, "Windows client");
                            FileAssertions.AssertContains(interopMatrixPath, "Windows server");
                            FileAssertions.AssertContains(interopMatrixPath, "Samba client");
                            FileAssertions.AssertContains(interopMatrixPath, "Samba server");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Bootstrap",
                        caseId: "ReadmeDoesNotClaimImplementedDialects",
                        displayName: "Repository README stays explicit about implementation status",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string readmePath = RepositoryPaths.FromRoot("README.md");
                            FileAssertions.AssertContains(readmePath, "The verified managed dialect surface now covers direct-TCP SMB 2.0.2, SMB 2.1, a bounded SMB 3.0 / SMB 3.0.2 slice, and a bounded SMB 3.1.1 opt-in preview slice.");
                            FileAssertions.AssertContains(readmePath, "By default the current managed client and server path prefer encryption-capable SMB 3.0.2");
                            FileAssertions.AssertContains(readmePath, "OpenCifsClientBuilder.WithSmb311Preview()");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Interop.Bootstrap",
                        caseId: "InteropSuitesExposePositiveAndNegativeVariants",
                        displayName: "Interop shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(InteropTestSuites.All, "Interop");
                            return Task.CompletedTask;
                        })
                });
        }

    }
}

