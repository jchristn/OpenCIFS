namespace OpenCIFS.Test.Xunit
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Test.Shared;
    using Touchstone.Core;
    using global::Xunit;
    using TouchstoneTestResult = Touchstone.Core.TestResult;

    /// <summary>
    /// xUnit adapter that executes every aggregate OpenCIFS Touchstone suite through
    /// a single aggregate fact.
    /// </summary>
    public sealed class OpenCifsFactTests
    {
        /// <summary>
        /// Execute every aggregate OpenCIFS Touchstone suite.
        /// </summary>
        /// <returns>Completion task.</returns>
        [Fact]
        public async Task RunAll()
        {
            CollectingResultSink sink = new CollectingResultSink();
            List<string> suiteFailures = new List<string>();

            foreach (TestSuiteDescriptor suite in AllSuites.All)
            {
                TestRunSummary summary = await TestExecutor.RunSuiteAsync(suite, sink, CancellationToken.None);

                if (!summary.IsSuccess)
                {
                    suiteFailures.Add($"{suite.SuiteId}: {summary.Failed} failed, {summary.Passed} passed, {summary.Skipped} skipped, {summary.Total} total");
                }
            }

            if (suiteFailures.Count > 0)
            {
                throw new InvalidOperationException(BuildFailureMessage(suiteFailures, sink.Failures));
            }
        }

        private static string BuildFailureMessage(IReadOnlyList<string> suiteFailures, IReadOnlyList<TouchstoneTestResult> caseFailures)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine("One or more Touchstone cases failed.");
            builder.AppendLine("Suite summary:");

            foreach (string suiteFailure in suiteFailures)
            {
                builder.Append(" - ");
                builder.AppendLine(suiteFailure);
            }

            if (caseFailures.Count > 0)
            {
                builder.AppendLine("Case failures:");

                foreach (TouchstoneTestResult caseFailure in caseFailures)
                {
                    builder.Append(" - ");
                    builder.Append(caseFailure.TestId);
                    builder.Append(": ");
                    builder.AppendLine(caseFailure.Message ?? caseFailure.Exception?.Message ?? "No failure message.");
                }
            }

            return builder.ToString();
        }

        private sealed class CollectingResultSink : ITestResultSink
        {
            private readonly List<TouchstoneTestResult> failures = new List<TouchstoneTestResult>();

            public IReadOnlyList<TouchstoneTestResult> Failures
            {
                get
                {
                    return this.failures;
                }
            }

            public ValueTask OnSuiteStartedAsync(TestSuiteDescriptor suite, CancellationToken cancellationToken)
            {
                return ValueTask.CompletedTask;
            }

            public ValueTask OnTestCompletedAsync(TouchstoneTestResult result, CancellationToken cancellationToken)
            {
                if (!result.Success && !result.Skipped)
                {
                    this.failures.Add(result);
                }

                return ValueTask.CompletedTask;
            }

            public ValueTask OnSuiteCompletedAsync(TestSuiteDescriptor suite, TestRunSummary summary, CancellationToken cancellationToken)
            {
                return ValueTask.CompletedTask;
            }
        }
    }
}
