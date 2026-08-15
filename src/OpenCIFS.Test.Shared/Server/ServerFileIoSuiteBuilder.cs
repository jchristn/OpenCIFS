namespace OpenCIFS.Server.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class ServerFileIoSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ServerFileIoBasicOperationCases.CreateCases());
            cases.AddRange(ServerFileIoValidationAndCallbackCases.CreateCases());
            cases.AddRange(ServerFileIoCreationAndOverwriteCases.CreateCases());
            cases.AddRange(ServerFileIoDeletionAndDispositionCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Server.FileIo",
                displayName: "Server file-I/O handling",
                cases: cases);
        }
    }
}
