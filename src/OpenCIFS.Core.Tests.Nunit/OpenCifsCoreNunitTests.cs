namespace OpenCIFS.Core.Tests.Nunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using OpenCIFS.Core.Tests.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit wrapper for the core Touchstone suites.
    /// </summary>
    [TestFixture]
    public sealed class OpenCifsCoreNunitTests : TouchstoneNunitBase
    {
        /// <summary>
        /// Shared suites executed by this runner.
        /// </summary>
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get
            {
                return CoreTestSuites.All;
            }
        }

        /// <summary>
        /// Execute all shared core suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Test]
        public async Task RunAll()
        {
            await RunAllAsync().ConfigureAwait(false);
        }
    }
}

