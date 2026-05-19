namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class ServerMetadataTrackedOpenMutationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            return new List<TestCaseDescriptor>
            {
                new TestCaseDescriptor(
                    suiteId: "Server.Metadata",
                    caseId: "ServerQueriesAndMutatesMetadataOnTrackedOpen",
                    displayName: "Server handles bounded query-info and set-info metadata operations on a tracked open",
                    executeAsync: ServerMetadataTrackedOpenMutationScenario.ExecuteAsync)
            };
        }
    }
}
