namespace OpenCIFS.Client.Tests.Mstest
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using OpenCIFS.Client.Tests.Shared;
    using Touchstone.Core;

    /// <summary>
    /// MSTest wrapper for the client Touchstone suites.
    /// </summary>
    [TestClass]
    public sealed class OpenCifsClientMstestTests
    {
        /// <summary>
        /// Execute all shared client suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [TestMethod]
        public async Task RunAll()
        {
            await ExecuteSuitesAsync(ClientTestSuites.All).ConfigureAwait(false);
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
