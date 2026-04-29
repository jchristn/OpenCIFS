namespace OpenCIFS.Client.Tests.Nunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using OpenCIFS.Client.Tests.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit wrapper for the client Touchstone suites.
    /// </summary>
    [TestFixture]
    public sealed class OpenCifsClientNunitTests : TouchstoneNunitBase
    {
        /// <summary>
        /// Shared suites executed by this runner.
        /// </summary>
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get
            {
                return ClientTestSuites.All;
            }
        }

        /// <summary>
        /// Execute all shared client suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Test]
        public async Task RunAll()
        {
            await RunAllAsync().ConfigureAwait(false);
        }
    }
}

