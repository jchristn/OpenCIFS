namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class ServerDefaultsSuiteBuilder
    {
        /// <summary>
        /// Build the server defaults suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ServerDefaultsSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ServerDefaultsOptionValidationCases.CreateCases());
            cases.AddRange(ServerDefaultsSampleProgramCases.CreateCases());
            cases.AddRange(ServerDefaultsShareAndBuilderCases.CreateCases());
            cases.AddRange(ServerDefaultsPublicSurfaceCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Server.Defaults",
                displayName: "Server bootstrap defaults",
                cases: cases);
        }
    }
}
