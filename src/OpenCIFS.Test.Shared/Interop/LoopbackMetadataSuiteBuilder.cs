namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class LoopbackMetadataSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(LoopbackMetadataAccessAndMutationCases.BuildCases());
            cases.AddRange(LoopbackMetadataValidationAndEnumerationCases.BuildCases());
            cases.AddRange(LoopbackMetadataRenameCases.BuildCases());
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackMetadata",
                displayName: "Loopback metadata coverage",
                cases: cases);
        }
    }
}
