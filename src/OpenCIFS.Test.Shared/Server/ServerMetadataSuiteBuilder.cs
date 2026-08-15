namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class ServerMetadataSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ServerMetadataAccessAndMutationCases.CreateCases());
            cases.AddRange(ServerMetadataCallbackAndDirectoryCases.CreateCases());
            cases.AddRange(ServerMetadataValidationCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Server.Metadata",
                displayName: "Server metadata handling",
                cases: cases);
        }
    }
}
