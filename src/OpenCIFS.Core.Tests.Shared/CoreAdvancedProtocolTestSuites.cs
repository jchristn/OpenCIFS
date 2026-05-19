namespace OpenCIFS.Core.Tests.Shared
{
    using Touchstone.Core;

    internal static class CoreAdvancedProtocolTestSuites
    {
        internal static TestSuiteDescriptor Smb2DurableHandleSuite()
        {
            return CoreAdvancedFileAndLeaseTestSuites.Smb2DurableHandleSuite();
        }

        internal static TestSuiteDescriptor Smb2LockSuite()
        {
            return CoreAdvancedFileAndLeaseTestSuites.Smb2LockSuite();
        }

        internal static TestSuiteDescriptor Smb2OplockBreakSuite()
        {
            return CoreAdvancedFileAndLeaseTestSuites.Smb2OplockBreakSuite();
        }

        internal static TestSuiteDescriptor Smb2LeaseSuite()
        {
            return CoreAdvancedFileAndLeaseTestSuites.Smb2LeaseSuite();
        }

        internal static TestSuiteDescriptor Smb2IoctlSuite()
        {
            return CoreAdvancedRpcAndContextTestSuites.Smb2IoctlSuite();
        }

        internal static TestSuiteDescriptor SrvsvcRpcSuite()
        {
            return CoreAdvancedRpcAndContextTestSuites.SrvsvcRpcSuite();
        }

        internal static TestSuiteDescriptor DfsReferralCodecSuite()
        {
            return CoreAdvancedRpcAndContextTestSuites.DfsReferralCodecSuite();
        }

        internal static TestSuiteDescriptor NegotiateContextSuite()
        {
            return CoreAdvancedRpcAndContextTestSuites.NegotiateContextSuite();
        }

        internal static TestSuiteDescriptor FsccCatalogSuite()
        {
            return CoreAdvancedCatalogAndParserTestSuites.FsccCatalogSuite();
        }

        internal static TestSuiteDescriptor StateLifecycleSuite()
        {
            return CoreAdvancedCatalogAndParserTestSuites.StateLifecycleSuite();
        }

        internal static TestSuiteDescriptor ParserMutationSuite()
        {
            return CoreAdvancedCatalogAndParserTestSuites.ParserMutationSuite();
        }
    }
}
