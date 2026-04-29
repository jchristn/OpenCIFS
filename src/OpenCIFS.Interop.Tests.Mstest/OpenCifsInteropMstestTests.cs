namespace OpenCIFS.Interop.Tests.Mstest
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using OpenCIFS.Interop.Tests.Shared;
    using Touchstone.Core;

    /// <summary>
    /// MSTest wrapper for the interoperability Touchstone suites.
    /// </summary>
    [TestClass]
    public sealed class OpenCifsInteropMstestTests
    {
        /// <summary>
        /// Execute all shared interoperability suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [TestMethod]
        public async Task RunAll()
        {
            await ExecuteSuitesAsync(InteropTestSuites.All).ConfigureAwait(false);
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
