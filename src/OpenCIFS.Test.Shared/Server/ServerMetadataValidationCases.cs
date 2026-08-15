namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;
    internal static class ServerMetadataValidationCases
    {
        internal static IReadOnlyList<TestCaseDescriptor> CreateCases()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ServerMetadataUnsupportedAccessCases.CreateCases());
            cases.AddRange(ServerMetadataIdentifierValidationCases.CreateCases());
            return cases;
        }
    }
}
