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
    internal static class ServerFileOperationTestSuites
    {
        internal static TestSuiteDescriptor ServerCompoundingSuite()
        {
            return ServerCompoundingSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ServerFileIoSuite()
        {
            return ServerFileIoSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ServerMetadataSuite()
        {
            return ServerMetadataSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ServerLockingSuite()
        {
            return ServerLockingSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor ServerIoctlSuite()
        {
            return ServerIoctlSuiteBuilder.Build();
        }
    }
}
