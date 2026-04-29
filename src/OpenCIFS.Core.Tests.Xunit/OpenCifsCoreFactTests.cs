namespace OpenCIFS.Core.Tests.Xunit
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using Touchstone.Core;
    using Xunit;

    /// <summary>
    /// xUnit wrapper for the core Touchstone suites.
    /// </summary>
    public sealed class OpenCifsCoreFactTests
    {
        /// <summary>
        /// Execute all shared core suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Fact]
        public async Task RunAll()
        {
            await ExecuteSuitesAsync(CoreTestSuites.All);
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
