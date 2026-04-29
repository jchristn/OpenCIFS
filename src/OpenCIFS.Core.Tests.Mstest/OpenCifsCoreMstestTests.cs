namespace OpenCIFS.Core.Tests.Mstest
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using OpenCIFS.Core.Tests.Shared;
    using Touchstone.Core;

    /// <summary>
    /// MSTest wrapper for the core Touchstone suites.
    /// </summary>
    [TestClass]
    public sealed class OpenCifsCoreMstestTests
    {
        /// <summary>
        /// Execute all shared core suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [TestMethod]
        public async Task RunAll()
        {
            await ExecuteSuitesAsync(CoreTestSuites.All).ConfigureAwait(false);
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
