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
    internal static class DialectCatalogSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Dialects",
                displayName: "Protocol dialect and enum catalogs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Dialects",
                        caseId: "AllPlannedDialectsPresent",
                        displayName: "All planned dialects are represented",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string[] names = Enum.GetNames(typeof(SmbDialect));

                            if (names.Length != 6)
                            {
                                throw new InvalidOperationException("Expected 6 planned dialects but found " + names.Length + ".");
                            }

                            AssertDialectPresent(names, nameof(SmbDialect.Cifs10));
                            AssertDialectPresent(names, nameof(SmbDialect.Smb2002));
                            AssertDialectPresent(names, nameof(SmbDialect.Smb21));
                            AssertDialectPresent(names, nameof(SmbDialect.Smb30));
                            AssertDialectPresent(names, nameof(SmbDialect.Smb302));
                            AssertDialectPresent(names, nameof(SmbDialect.Smb311));
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Dialects",
                        caseId: "EnumWireValuesRemainStable",
                        displayName: "Enum wire values remain stable",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Equal((byte)0x72, (byte)Smb1Command.Negotiate, "SMB1 negotiate command value changed.");
                            TestAssertions.Equal((ushort)0x0008, (ushort)Smb2Command.Read, "SMB2 read command value changed.");
                            TestAssertions.Equal((ushort)0x8000, (ushort)Smb1HeaderFlags2.Unicode, "SMB1 Unicode flag value changed.");
                            TestAssertions.Equal((uint)0x00000040U, (uint)Smb2GlobalCapabilities.Encryption, "SMB2 encryption capability value changed.");
                            TestAssertions.Equal((uint)0xC0000022U, (uint)NtStatus.AccessDenied, "NTSTATUS AccessDenied value changed.");
                            TestAssertions.Equal((uint)0xC0000043U, (uint)NtStatus.SharingViolation, "NTSTATUS SharingViolation value changed.");
                            TestAssertions.Equal((uint)0xC0000056U, (uint)NtStatus.DeletePending, "NTSTATUS DeletePending value changed.");
                            TestAssertions.Equal((ushort)0x0001, (ushort)HashAlgorithmId.Sha512, "Preauth hash algorithm value changed.");
                            TestAssertions.Equal((ushort)0x0002, (ushort)SigningAlgorithmId.AesGmac, "Signing algorithm value changed.");
                            TestAssertions.Equal((ushort)0x0008, (ushort)Smb2NegotiateContextType.SigningCapabilities, "Negotiate context type value changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Dialects",
                        caseId: "DialectCatalogRejectsUnknownWireValuesAndInvalidRanges",
                        displayName: "Dialect catalog rejects unknown wire values and invalid ranges",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            bool found = SmbDialectCatalog.TryFromSmb2WireDialect(0xFFFF, out SmbDialect unknownDialect);
                            TestAssertions.False(found, "Unknown SMB2 wire dialects should not resolve.");
                            TestAssertions.Equal(default, unknownDialect, "Unknown SMB2 wire dialects should leave the dialect output at its default value.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => SmbDialectCatalog.ToSmb2WireDialect(SmbDialect.Cifs10),
                                "SMB1 dialects must not map to SMB2/3 wire dialect values.");
                            TestAssertions.Throws<ArgumentException>(
                                () => SmbDialectCatalog.GetSmb2DialectsInRange(SmbDialect.Smb311, SmbDialect.Smb2002),
                                "Descending SMB2/3 dialect ranges should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }
    }
}
