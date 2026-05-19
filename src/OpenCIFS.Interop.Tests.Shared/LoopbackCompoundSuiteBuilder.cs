namespace OpenCIFS.Interop.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class LoopbackCompoundSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(LoopbackCompoundBaselineCases.CreateCases());
            cases.AddRange(LoopbackCompoundRealisticCases.CreateCases());
            cases.AddRange(LoopbackCompoundValidationCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Interop.LoopbackCompound",
                displayName: "Loopback SMB2 compounding coverage",
                cases: cases);
        }
    }
}
