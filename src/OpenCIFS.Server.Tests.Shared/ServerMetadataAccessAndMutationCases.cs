namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;
    internal static class ServerMetadataAccessAndMutationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ServerMetadataShareModeCases.CreateCases());
            cases.AddRange(ServerMetadataTrackedOpenMutationCases.CreateCases());
            cases.AddRange(ServerMetadataReadOnlyDispositionCases.CreateCases());
            return cases;
        }
    }
}
