namespace OpenCIFS.Core.Tests.Shared
{
    using System;
    using System.Buffers;
    using System.Collections.Generic;
    using System.IO;
    using System.IO.Pipelines;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Security;
    using OpenCIFS.Transport;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;
    using Touchstone.Core;
    using static OpenCIFS.Core.Tests.Shared.CoreTestSupport;
    internal static class CoreBootstrapAndNegotiationTestSuites
    {
        internal static TestSuiteDescriptor RepositoryBootstrapSuite()
        {
            return RepositoryBootstrapSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor DialectCatalogSuite()
        {
            return DialectCatalogSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor PrimitiveCodecSuite()
        {
            return PrimitiveCodecSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor FrameFoundationSuite()
        {
            return FrameFoundationSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor HeaderFoundationSuite()
        {
            return HeaderFoundationSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2CompoundSuite()
        {
            return Smb2CompoundSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2NegotiateSuite()
        {
            return Smb2NegotiateSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb1NegotiateResponseSuite()
        {
            return Smb1NegotiateResponseSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2SessionTreeSuite()
        {
            return Smb2SessionTreeSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2EchoSuite()
        {
            return Smb2EchoSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2CancelSuite()
        {
            return Smb2CancelSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2ChangeNotifySuite()
        {
            return Smb2ChangeNotifySuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor Smb2FileIoSuite()
        {
            return Smb2FileIoSuiteBuilder.Build();
        }

        internal static TestSuiteDescriptor MetadataSuite()
        {
            return MetadataSuiteBuilder.Build();
        }
    }
}
