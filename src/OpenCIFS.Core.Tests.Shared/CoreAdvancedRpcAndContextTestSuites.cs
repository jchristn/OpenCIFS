namespace OpenCIFS.Core.Tests.Shared
{
    using Touchstone.Core;

    internal static class CoreAdvancedRpcAndContextTestSuites
    {
        internal static TestSuiteDescriptor Smb2IoctlSuite()
        {
            return CoreSmb2IoctlSuiteBuilder.Smb2IoctlSuite();
        }

        internal static TestSuiteDescriptor SrvsvcRpcSuite()
        {
            return CoreSrvsvcRpcSuiteBuilder.SrvsvcRpcSuite();
        }

        internal static TestSuiteDescriptor DfsReferralCodecSuite()
        {
            return CoreDfsReferralCodecSuiteBuilder.DfsReferralCodecSuite();
        }

        internal static TestSuiteDescriptor NegotiateContextSuite()
        {
            return CoreNegotiateContextSuiteBuilder.NegotiateContextSuite();
        }
    }
}
