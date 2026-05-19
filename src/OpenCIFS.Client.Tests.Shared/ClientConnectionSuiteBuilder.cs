namespace OpenCIFS.Client.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Client.Tests.Shared.ClientTestSupport;
    internal static class ClientConnectionSuiteBuilder
    {
        /// <summary>
        /// Build the managed direct-TCP client connection suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        internal static TestSuiteDescriptor Build()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();
            cases.AddRange(ClientConnectionSurfaceAndLifecycleCases.BuildCases());
            cases.AddRange(ClientConnectionNotificationAndCoordinationCases.BuildCases());
            cases.AddRange(ClientConnectionDurabilityAndCompoundCases.BuildCases());
            return new TestSuiteDescriptor(
                suiteId: "Client.Connection",
                displayName: "Client direct-TCP connection handling",
                cases: cases);
        }
    }
}
