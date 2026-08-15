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
    internal static class ClientNotificationAndHighLevelTestSuites
    {

        internal static TestSuiteDescriptor ClientChangeNotifySuite()
        {
            return ClientChangeNotifySuiteBuilder.ClientChangeNotifySuite();
        }

        internal static TestSuiteDescriptor ClientOplockSuite()
        {
            return ClientOplockSuiteBuilder.ClientOplockSuite();
        }

        internal static TestSuiteDescriptor ClientLeaseSuite()
        {
            return ClientLeaseSuiteBuilder.ClientLeaseSuite();
        }

        internal static TestSuiteDescriptor ClientPrimarySuite()
        {
            return ClientPrimarySuiteBuilder.ClientPrimarySuite();
        }

        internal static TestSuiteDescriptor ClientFacadeSuite()
        {
            return ClientFacadeSuiteBuilder.ClientFacadeSuite();
        }
    }
}
