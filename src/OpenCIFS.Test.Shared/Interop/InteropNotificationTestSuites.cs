namespace OpenCIFS.Interop.Tests.Shared
{
    using Touchstone.Core;

    internal static class InteropNotificationTestSuites
    {
        internal static TestSuiteDescriptor LoopbackChangeNotifySuite()
        {
            return LoopbackChangeNotifySuiteBuilder.LoopbackChangeNotifySuite();
        }

        internal static TestSuiteDescriptor LoopbackOplockSuite()
        {
            return LoopbackOplockSuiteBuilder.LoopbackOplockSuite();
        }

        internal static TestSuiteDescriptor LoopbackLeaseSuite()
        {
            return LoopbackLeaseSuiteBuilder.LoopbackLeaseSuite();
        }

        internal static TestSuiteDescriptor LoopbackDurableHandleSuite()
        {
            return LoopbackDurableHandleSuiteBuilder.LoopbackDurableHandleSuite();
        }
    }
}
