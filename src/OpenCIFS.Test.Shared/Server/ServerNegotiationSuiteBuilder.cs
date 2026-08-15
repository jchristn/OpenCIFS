namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class ServerNegotiationSuiteBuilder
    {
        /// <summary>
        /// Build the server negotiate suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor ServerNegotiationSuite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ServerNegotiationBaselineCases.CreateCases());
            cases.AddRange(ServerNegotiationSmb311RequestAndPreviewCases.CreateCases());
            cases.AddRange(ServerNegotiationDirectTcpCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Server.Negotiate",
                displayName: "Server negotiate handling",
                cases: cases);
        }
    }
}
