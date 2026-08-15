namespace OpenCIFS.Interop.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class LoopbackFileIoSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(LoopbackFileIoLifecycleCases.CreateCases());
            cases.AddRange(LoopbackFileIoPendingAndValidationCases.CreateCases());
            cases.AddRange(LoopbackFileIoCreationAndOverwriteCases.CreateCases());
            cases.AddRange(LoopbackFileIoAttributeAndReadonlyCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackFileIo",
                displayName: "Loopback file-I/O coverage",
                cases: cases);
        }
    }
}
