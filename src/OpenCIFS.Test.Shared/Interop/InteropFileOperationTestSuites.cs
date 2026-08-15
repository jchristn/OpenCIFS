namespace OpenCIFS.Interop.Tests.Shared
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using OpenCIFS.Client;
    using OpenCIFS.Core.Tests.Shared;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;
    using Touchstone.Core;
    using static OpenCIFS.Interop.Tests.Shared.InteropTestSupport;
    internal static class InteropFileOperationTestSuites
    {
        internal static TestSuiteDescriptor LoopbackCompoundSuite()
        {
            return LoopbackCompoundSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor LoopbackFileIoSuite()
        {
            return LoopbackFileIoSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor LoopbackMetadataSuite()
        {
            return LoopbackMetadataSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor LoopbackLockingSuite()
        {
            return LoopbackLockingSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor LoopbackIoctlSuite()
        {
            return LoopbackIoctlSuiteBuilder.Build();
        }
    }
}
