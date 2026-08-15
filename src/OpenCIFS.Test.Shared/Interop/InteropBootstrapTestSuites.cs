namespace OpenCIFS.Interop.Tests.Shared
{
    using Touchstone.Core;

    internal static class InteropBootstrapTestSuites
    {
        internal static TestSuiteDescriptor InteropArtifactsSuite()
        {
            return InteropBootstrapArtifactsSuiteBuilder.InteropArtifactsSuite();
        }

        internal static TestSuiteDescriptor LoopbackNegotiateSuite()
        {
            return InteropLoopbackNegotiateSuiteBuilder.LoopbackNegotiateSuite();
        }

        internal static TestSuiteDescriptor LoopbackSessionTreeSuite()
        {
            return InteropLoopbackSessionTreeSuiteBuilder.LoopbackSessionTreeSuite();
        }

        internal static TestSuiteDescriptor LoopbackEchoSuite()
        {
            return InteropLoopbackEchoSuiteBuilder.LoopbackEchoSuite();
        }

        internal static TestSuiteDescriptor LoopbackCreditHeaderSuite()
        {
            return InteropLoopbackCreditHeaderSuiteBuilder.LoopbackCreditHeaderSuite();
        }
    }
}
