namespace OpenCIFS.Server.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Formats.Asn1;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Net.Sockets;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Server;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Sample.OpenCifsServer;
    using Touchstone.Core;
    using static OpenCIFS.Server.Tests.Shared.ServerTestSupport;
    internal static class ServerBootstrapAndNegotiationTestSuites
    {

        internal static TestSuiteDescriptor ServerDefaultsSuite()
        {
            return ServerDefaultsSuiteBuilder.ServerDefaultsSuite();
        }

        internal static TestSuiteDescriptor ServerNegotiationSuite()
        {
            return ServerNegotiationSuiteBuilder.ServerNegotiationSuite();
        }

        internal static TestSuiteDescriptor ServerSessionTreeSuite()
        {
            return ServerSessionTreeSuiteBuilder.ServerSessionTreeSuite();
        }

        internal static TestSuiteDescriptor ServerEchoSuite()
        {
            return ServerEchoSuiteBuilder.ServerEchoSuite();
        }

        internal static TestSuiteDescriptor ServerCreditHeaderSuite()
        {
            return ServerCreditHeaderSuiteBuilder.ServerCreditHeaderSuite();
        }

        internal static TestSuiteDescriptor ServerDfsConfigurationSuite()
        {
            return ServerDfsConfigurationSuiteBuilder.ServerDfsConfigurationSuite();
        }
    }
}
