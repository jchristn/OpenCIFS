namespace OpenCIFS.Interop.Tests.Xunit
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Interop.Tests.Shared;
    using Touchstone.Core;
    using Xunit;

    /// <summary>
    /// xUnit wrapper for the interoperability Touchstone suites.
    /// </summary>
    public sealed class OpenCifsInteropFactTests
    {
        /// <summary>
        /// Execute all shared interoperability suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Fact]
        public async Task RunAll()
        {
            await ExecuteSuitesAsync(InteropTestSuites.All);
        }

        private static async Task ExecuteSuitesAsync(IReadOnlyList<TestSuiteDescriptor> suites)
        {
            for (int suiteIndex = 0; suiteIndex < suites.Count; suiteIndex++)
            {
                TestSuiteDescriptor suite = suites[suiteIndex];

                for (int caseIndex = 0; caseIndex < suite.Cases.Count; caseIndex++)
                {
                    TestCaseDescriptor descriptor = suite.Cases[caseIndex];

                    if (!descriptor.Skip)
                    {
                        await descriptor.ExecuteAsync(CancellationToken.None).ConfigureAwait(false);
                    }
                }
            }
        }
    }
}
