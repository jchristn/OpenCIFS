namespace OpenCIFS.Server.Tests.Shared
{
    using Touchstone.Core;

    internal static class ServerNotificationAndDurabilityTestSuites
    {
        internal static TestSuiteDescriptor ServerChangeNotifySuite()
        {
            return ServerChangeNotifySuiteBuilder.ServerChangeNotifySuite();
        }

        internal static TestSuiteDescriptor ServerOplockSuite()
        {
            return ServerOplockSuiteBuilder.ServerOplockSuite();
        }

        internal static TestSuiteDescriptor ServerLeaseSuite()
        {
            return ServerLeaseSuiteBuilder.ServerLeaseSuite();
        }

        internal static TestSuiteDescriptor ServerDurableHandleSuite()
        {
            return ServerDurableHandleSuiteBuilder.ServerDurableHandleSuite();
        }

        internal static TestSuiteDescriptor ServerMutationSuite()
        {
            return ServerMutationSuiteBuilder.ServerMutationSuite();
        }
    }
}
