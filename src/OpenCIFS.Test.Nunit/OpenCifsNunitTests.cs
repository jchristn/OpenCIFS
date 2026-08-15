namespace OpenCIFS.Test.Nunit
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using NUnit.Framework;
    using OpenCIFS.Test.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit adapter that executes every aggregate OpenCIFS Touchstone suite through
    /// the Touchstone NUnit adapter base class.
    /// </summary>
    [TestFixture]
    public sealed class OpenCifsNunitTests : TouchstoneNunitBase
    {
        /// <summary>
        /// The aggregate suites executed by this adapter.
        /// </summary>
        protected override IReadOnlyList<TestSuiteDescriptor> Suites
        {
            get
            {
                return AllSuites.All;
            }
        }

        /// <summary>
        /// Execute every aggregate OpenCIFS Touchstone suite.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Test]
        public async Task RunAll()
        {
            await RunAllAsync().ConfigureAwait(false);
        }
    }
}
