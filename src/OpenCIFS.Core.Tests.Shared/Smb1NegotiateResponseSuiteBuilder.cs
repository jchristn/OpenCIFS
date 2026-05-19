namespace OpenCIFS.Core.Tests.Shared
{
    using System.Collections.Generic;
    using Touchstone.Core;

    internal static class Smb1NegotiateResponseSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(Smb1NegotiationSessionAndTreeCases.CreateCases());
            cases.AddRange(Smb1AdministrativeCommandCases.CreateCases());
            cases.AddRange(Smb1FileIoCommandCases.CreateCases());
            cases.AddRange(Smb1TransactionRequestCases.CreateCases());
            cases.AddRange(Smb1TransactionResponseAndStatusCases.CreateCases());
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb1Negotiate",
                displayName: "Bounded SMB1 NEGOTIATE response codec",
                cases: cases);
        }
    }
}
