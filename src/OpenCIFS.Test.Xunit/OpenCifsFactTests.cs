namespace OpenCIFS.Test.Xunit
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Test.Shared;
    using Touchstone.Core;
    using Touchstone.XunitAdapter;
    using global::Xunit;

    /// <summary>
    /// xUnit adapter that executes every aggregate OpenCIFS Touchstone suite through
    /// the Touchstone xUnit adapter base class.
    /// </summary>
    public sealed class OpenCifsFactTests : TouchstoneFactBase
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
        [Fact]
        public async Task RunAll()
        {
            await RunAllAsync(CancellationToken.None);
        }
    }
}
