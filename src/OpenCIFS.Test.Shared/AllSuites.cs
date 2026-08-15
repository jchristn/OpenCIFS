namespace OpenCIFS.Test.Shared
{
    using System.Collections.Generic;
    using OpenCIFS.Client.Tests.Shared;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Interop.Tests.Shared;
    using OpenCIFS.Server.Tests.Shared;
    using Touchstone.Core;

    /// <summary>
    /// Central Touchstone source of truth that aggregates every OpenCIFS shared suite
    /// across the Core, Server, Client, and Interop domains. Every runner adapter
    /// (automated CLI, xUnit, and NUnit) executes exactly this aggregate.
    /// </summary>
    public static class AllSuites
    {
        /// <summary>
        /// All shared Touchstone suites for the entire OpenCIFS platform, in execution order:
        /// protocol/core foundations, then server, then client, then in-process interop loopback.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                List<TestSuiteDescriptor> suites = new List<TestSuiteDescriptor>();
                suites.AddRange(CoreTestSuites.All);
                suites.AddRange(ServerTestSuites.All);
                suites.AddRange(ClientTestSuites.All);
                suites.AddRange(InteropTestSuites.All);
                return suites;
            }
        }
    }
}
