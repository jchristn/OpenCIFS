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
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;
    internal static class ClientBootstrapAndNegotiationTestSuites
    {
        internal static TestSuiteDescriptor ClientDefaultsSuite()
        {
            return ClientDefaultsSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ClientNegotiationSuite()
        {
            return ClientNegotiationSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ClientSessionTreeSuite()
        {
            return ClientSessionTreeSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ClientEchoSuite()
        {
            return ClientEchoSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ClientCreditHeaderSuite()
        {
            return ClientCreditHeaderSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ClientConnectionSuite()
        {
            return ClientConnectionSuiteBuilder.Build();
        }
    }
}
