namespace OpenCIFS.Interop.Tests.Nunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using OpenCIFS.Interop.Tests.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit wrapper for the interoperability Touchstone suites.
    /// </summary>
    [TestFixture]
    public sealed class OpenCifsInteropNunitTests : TouchstoneNunitBase
    {
        /// <summary>
        /// Shared suites executed by this runner.
        /// </summary>
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get
            {
                return InteropTestSuites.All;
            }
        }

        /// <summary>
        /// Execute all shared interoperability suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Test]
        public async Task RunAll()
        {
            await RunAllAsync().ConfigureAwait(false);
        }
    }
}

