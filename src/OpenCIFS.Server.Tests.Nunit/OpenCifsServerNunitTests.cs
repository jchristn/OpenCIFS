namespace OpenCIFS.Server.Tests.Nunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using OpenCIFS.Server.Tests.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit wrapper for the server Touchstone suites.
    /// </summary>
    [TestFixture]
    public sealed class OpenCifsServerNunitTests : TouchstoneNunitBase
    {
        /// <summary>
        /// Shared suites executed by this runner.
        /// </summary>
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get
            {
                return ServerTestSuites.All;
            }
        }

        /// <summary>
        /// Execute all shared server suites.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Test]
        public async Task RunAll()
        {
            await RunAllAsync().ConfigureAwait(false);
        }
    }
}

