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

    /// <summary>
    /// Shared Touchstone suites for repository bootstrap and protocol foundation coverage.
    /// </summary>
    public static class CoreTestSuites
    {
        /// <summary>
        /// All shared core test suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    RepositoryBootstrapSuite(),
                    DialectCatalogSuite(),
                    PrimitiveCodecSuite(),
                    FrameFoundationSuite(),
                    HeaderFoundationSuite(),
                    Smb2CompoundSuite(),
                    Smb2NegotiateSuite(),
                    Smb1NegotiateResponseSuite(),
                    Smb2SessionTreeSuite(),
                    Smb2EchoSuite(),
                    Smb2CancelSuite(),
                    Smb2ChangeNotifySuite(),
                    Smb2FileIoSuite(),
                    Smb2DurableHandleSuite(),
                    Smb2LockSuite(),
                    Smb2OplockBreakSuite(),
                    Smb2LeaseSuite(),
                    Smb2IoctlSuite(),
                    SrvsvcRpcSuite(),
                    DfsReferralCodecSuite(),
                    MetadataSuite(),
                    NegotiateContextSuite(),
                    FsccCatalogSuite(),
                    StateLifecycleSuite(),
                    ParserMutationSuite(),
                    SecurityFoundationSuite(),
                    TransportFoundationSuite()
                };
            }
        }

        /// <summary>
        /// Build the repository bootstrap suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor RepositoryBootstrapSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Bootstrap",
                displayName: "Core bootstrap artifacts",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "RequiredArtifactsExist",
                        displayName: "Required repository artifacts exist",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string repositoryRoot = RepositoryPaths.GetRepositoryRoot();
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "README.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "CHANGELOG.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "LICENSE.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "docs", "coverage-matrix.md"));
                            FileAssertions.AssertExists(Path.Combine(repositoryRoot, "docs", "interop-matrix.md"));
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "CoverageMatrixTemplatePresent",
                        displayName: "Coverage matrix template includes required headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string coverageMatrixPath = RepositoryPaths.FromRoot(Path.Combine("docs", "coverage-matrix.md"));
                            FileAssertions.AssertContains(coverageMatrixPath, "| dialect | area | command or capability |");
                            FileAssertions.AssertContains(coverageMatrixPath, "| SMB 3.1.1 | negotiate contexts |");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "FileAssertionsRejectMissingArtifactsAndHeaders",
                        displayName: "Bootstrap file assertions reject missing artifacts and headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string tempDirectory = TestPathUtilities.CreateUniqueDirectory("OpenCifsBootstrapAssertions_");

                            try
                            {
                                string missingFilePath = Path.Combine(tempDirectory, "missing.md");
                                string coverageMatrixPath = Path.Combine(tempDirectory, "coverage-matrix.md");
                                File.WriteAllText(coverageMatrixPath, "| dialect | area | command or capability |");

                                TestAssertions.Throws<FileNotFoundException>(
                                    () => FileAssertions.AssertExists(missingFilePath),
                                    "Expected bootstrap file assertions to reject missing repository artifacts.");
                                TestAssertions.Throws<InvalidOperationException>(
                                    () => FileAssertions.AssertContains(coverageMatrixPath, "| SMB 3.1.1 | negotiate contexts |"),
                                    "Expected bootstrap file assertions to reject incomplete coverage matrix content.");
                            }
                            finally
                            {
                                TestPathUtilities.DeleteDirectoryForcefully(tempDirectory);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "SharedTestUtilitiesExposeDeterministicRootsVectorsAndPacketTraces",
                        displayName: "Shared test utilities expose deterministic roots, vectors, clocks, and packet traces",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = TestPathUtilities.CreateUniqueDirectory("OpenCifsSharedUtilities_");

                            try
                            {
                                TestAssertions.True(Directory.Exists(rootPath), "Expected the shared test path helper to create the requested directory.");
                                TestAssertions.Equal(
                                    DeterministicTestClock.GetUtc("Core.Bootstrap.UtilityClock"),
                                    DeterministicTestClock.GetUtc("Core.Bootstrap.UtilityClock"),
                                    "Expected the deterministic test clock to return the same timestamp for the same key.");
                                TestAssertions.SequenceEqual(
                                    Hex("31D6CFE0D16AE931B73C59D7E0C089C0"),
                                    GoldenVectorStore.GetBytes("core.security.md4.empty"),
                                    "Expected the golden-vector store to return the stored MD4 empty-string vector.");

                                PacketCaptureTraceWriter traceWriter = new PacketCaptureTraceWriter(rootPath, "CoreBootstrapUtilityTrace");
                                traceWriter.Capture("negotiate-request", new byte[] { 0x01, 0x02, 0x03 });
                                traceWriter.Capture("negotiate-response", new byte[] { 0x11, 0x12 });
                                string manifestPath = traceWriter.WriteManifest();

                                FileAssertions.AssertExists(manifestPath);
                                FileAssertions.AssertContains(manifestPath, "\"packet_count\": 2");
                                FileAssertions.AssertContains(manifestPath, "negotiate-request");
                                FileAssertions.AssertContains(manifestPath, "negotiate-response");
                            }
                            finally
                            {
                                TestPathUtilities.DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "SharedTestUtilitiesRejectInvalidArguments",
                        displayName: "Shared test utilities reject invalid arguments and missing vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            string rootPath = TestPathUtilities.CreateUniqueDirectory("OpenCifsSharedUtilitiesNegative_");

                            try
                            {
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => TestPathUtilities.CreateUniqueDirectory(" "),
                                    "Expected the shared test path helper to reject empty prefixes.");
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => DeterministicTestClock.GetUtc(" "),
                                    "Expected the deterministic clock helper to reject empty keys.");
                                TestAssertions.Throws<KeyNotFoundException>(
                                    () => GoldenVectorStore.GetString("core.security.missing.vector"),
                                    "Expected the golden-vector store to reject unknown vector names.");
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => new PacketCaptureTraceWriter(rootPath, " "),
                                    "Expected the packet-capture helper to reject empty trace names.");

                                PacketCaptureTraceWriter traceWriter = new PacketCaptureTraceWriter(rootPath, "NegativeTrace");
                                TestAssertions.Throws<ArgumentNullException>(
                                    () => traceWriter.Capture(" ", new byte[] { 0x00 }),
                                    "Expected the packet-capture helper to reject empty capture labels.");
                            }
                            finally
                            {
                                TestPathUtilities.DeleteDirectoryForcefully(rootPath);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Bootstrap",
                        caseId: "CoreSuitesExposePositiveAndNegativeVariants",
                        displayName: "Core shared suites expose positive and negative variants",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();
                            TestCaseVariantCoverage.AssertBalancedVariants(All, "Core");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the dialect catalog suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor DialectCatalogSuite()
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

        /// <summary>
        /// Build the primitive codec suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor PrimitiveCodecSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Primitives",
                displayName: "Primitive binary codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Primitives",
                        caseId: "LittleEndianReaderWriterRoundTrip",
                        displayName: "Little-endian reader and writer round-trip deterministic values",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            LittleEndianWriter writer = new LittleEndianWriter();
                            writer.WriteByte(0xAB);
                            writer.WriteUInt16(0x1234);
                            writer.WriteUInt24BigEndian(0x00ABCDEF);
                            writer.WriteUInt32(0x55667788);
                            writer.WriteUInt32BigEndian(0xA1B2C3D4);
                            writer.WriteUInt64(0x0102030405060708);
                            writer.WriteBytes(new byte[] { 0xDE, 0xAD });

                            TestAssertions.Equal(24, writer.Length, "Unexpected encoded byte count.");

                            LittleEndianReader reader = new LittleEndianReader(writer.ToArray());
                            TestAssertions.Equal((byte)0xAB, reader.ReadByte(), "Unexpected byte value.");
                            TestAssertions.Equal((ushort)0x1234, reader.ReadUInt16(), "Unexpected UInt16 value.");
                            TestAssertions.Equal(0x00ABCDEFU, reader.ReadUInt24BigEndian(), "Unexpected UInt24 value.");
                            TestAssertions.Equal(0x55667788U, reader.ReadUInt32(), "Unexpected UInt32 value.");
                            TestAssertions.Equal(0xA1B2C3D4U, reader.ReadUInt32BigEndian(), "Unexpected big-endian UInt32 value.");
                            TestAssertions.Equal(0x0102030405060708UL, reader.ReadUInt64(), "Unexpected UInt64 value.");
                            TestAssertions.SequenceEqual(new byte[] { 0xDE, 0xAD }, reader.ReadBytes(2), "Unexpected trailing bytes.");
                            TestAssertions.Equal(0, reader.RemainingBytes, "Reader should be at the end of the buffer.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Primitives",
                        caseId: "PrimitiveReadersRejectMalformedInputs",
                        displayName: "Primitive readers reject malformed and oversized inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            LittleEndianReader truncatedReader = new LittleEndianReader(new byte[] { 0x01, 0x02, 0x03 });
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => truncatedReader.ReadUInt32(),
                                "Reading a truncated UInt32 should fail.");

                            LittleEndianReader skipReader = new LittleEndianReader(new byte[] { 0x01 });
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => skipReader.Skip(2),
                                "Skipping beyond the buffer should fail.");

                            LittleEndianWriter writer = new LittleEndianWriter();
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => writer.WriteUInt24BigEndian(0x01000000U),
                                "Writing a value larger than 24 bits should fail.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the frame foundation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor FrameFoundationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Frames",
                displayName: "Frame header foundations",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Frames",
                        caseId: "DirectTcpHeaderRoundTrip",
                        displayName: "Direct TCP frame headers round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            DirectTcpFrameHeader header = new DirectTcpFrameHeader
                            {
                                Length = 4096
                            };

                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(DirectTcpFrameHeader.Size, encoded.Length, "Unexpected Direct TCP header length.");

                            DirectTcpFrameHeader parsed = DirectTcpFrameHeader.ReadFrom(encoded);
                            DirectTcpFrameValidator.Validate(parsed);
                            TestAssertions.Equal(4096, parsed.Length, "Unexpected Direct TCP payload length.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Frames",
                        caseId: "NetBiosHeaderRoundTrip",
                        displayName: "NetBIOS session service headers round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
                            {
                                MessageType = NetBiosSessionMessageType.SessionKeepAlive,
                                Length = 1024
                            };

                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(NetBiosSessionServiceHeader.Size, encoded.Length, "Unexpected NetBIOS header length.");

                            NetBiosSessionServiceHeader parsed = NetBiosSessionServiceHeader.ReadFrom(encoded);
                            NetBiosSessionServiceValidator.Validate(parsed);
                            TestAssertions.Equal(NetBiosSessionMessageType.SessionKeepAlive, parsed.MessageType, "Unexpected NetBIOS message type.");
                            TestAssertions.Equal(1024, parsed.Length, "Unexpected NetBIOS payload length.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Frames",
                        caseId: "FrameHeadersRejectMalformedInputs",
                        displayName: "Frame header readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DirectTcpFrameHeader.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "A truncated Direct TCP header should fail to parse.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => DirectTcpFrameValidator.Validate(null!),
                                "A null Direct TCP header should fail validation.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosSessionServiceHeader.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "A truncated NetBIOS header should fail to parse.");

                            NetBiosSessionServiceHeader invalidHeader = new NetBiosSessionServiceHeader
                            {
                                MessageType = (NetBiosSessionMessageType)0x7F,
                                Length = 1
                            };

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => NetBiosSessionServiceValidator.Validate(invalidHeader),
                                "An unknown NetBIOS message type should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB header suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor HeaderFoundationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Headers",
                displayName: "SMB header codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "Smb1HeaderRoundTrip",
                        displayName: "SMB1 headers round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1Header header = CreateValidSmb1Header();
                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(32, encoded.Length, "Unexpected SMB1 header size.");

                            Smb1Header parsed = Smb1Header.ReadFrom(encoded);
                            Smb1HeaderValidator.Validate(parsed);
                            TestAssertions.Equal(Smb1Command.WriteAndX, parsed.Command, "Unexpected SMB1 command.");
                            TestAssertions.Equal(NtStatus.AccessDenied, parsed.Status, "Unexpected SMB1 status.");
                            TestAssertions.Equal(Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply, parsed.Flags, "Unexpected SMB1 flags.");
                            TestAssertions.Equal(Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity, parsed.Flags2, "Unexpected SMB1 flags2.");
                            TestAssertions.Equal((ushort)0x1234, parsed.ProcessIdHigh, "Unexpected SMB1 PID high.");
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 }, parsed.Signature, "Unexpected SMB1 signature.");
                            TestAssertions.Equal((ushort)0x4567, parsed.TreeId, "Unexpected SMB1 tree identifier.");
                            TestAssertions.Equal((ushort)0x89AB, parsed.ProcessIdLow, "Unexpected SMB1 PID low.");
                            TestAssertions.Equal((ushort)0xCDEF, parsed.UserId, "Unexpected SMB1 user identifier.");
                            TestAssertions.Equal((ushort)0x2468, parsed.MultiplexId, "Unexpected SMB1 multiplex identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "Smb2HeaderRoundTrip",
                        displayName: "SMB2 headers round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header header = CreateValidSmb2Header();
                            byte[] encoded = header.ToByteArray();
                            TestAssertions.Equal(64, encoded.Length, "Unexpected SMB2 header size.");

                            Smb2Header parsed = Smb2Header.ReadFrom(encoded);
                            Smb2HeaderValidator.Validate(parsed);
                            TestAssertions.Equal((ushort)2, parsed.CreditCharge, "Unexpected SMB2 credit charge.");
                            TestAssertions.Equal(NtStatus.BufferTooSmall, parsed.Status, "Unexpected SMB2 status.");
                            TestAssertions.Equal(Smb2Command.QueryInfo, parsed.Command, "Unexpected SMB2 command.");
                            TestAssertions.Equal((ushort)7, parsed.CreditRequest, "Unexpected SMB2 credit request.");
                            TestAssertions.Equal(Smb2HeaderFlags.Signed | Smb2HeaderFlags.ServerToRedir, parsed.Flags, "Unexpected SMB2 flags.");
                            TestAssertions.Equal(16U, parsed.NextCommand, "Unexpected SMB2 next-command offset.");
                            TestAssertions.Equal(0x0102030405060708UL, parsed.MessageId, "Unexpected SMB2 message identifier.");
                            TestAssertions.Equal(0x0A0B0C0DU, parsed.ProcessId, "Unexpected SMB2 process identifier.");
                            TestAssertions.Equal(0x10203040U, parsed.TreeId, "Unexpected SMB2 tree identifier.");
                            TestAssertions.Equal(0x1122334455667788UL, parsed.SessionId, "Unexpected SMB2 session identifier.");
                            TestAssertions.SequenceEqual(
                                new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F },
                                parsed.Signature,
                                "Unexpected SMB2 signature.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "Smb2002HeaderAllowsReservedCreditCharge",
                        displayName: "SMB 2.0.2 headers allow the reserved CreditCharge field to remain zero",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header header = CreateValidSmb2Header();
                            header.CreditCharge = 0;
                            header.Command = Smb2Command.Negotiate;
                            header.CreditRequest = 3;
                            header.Flags = Smb2HeaderFlags.None;
                            header.NextCommand = 0;
                            header.MessageId = 0;
                            header.ProcessId = 0;
                            header.TreeId = 0;
                            header.SessionId = 0;
                            header.Signature = new byte[16];

                            Smb2Header parsed = Smb2Header.ReadFrom(header.ToByteArray());
                            Smb2HeaderValidator.Validate(parsed);
                            TestAssertions.Equal((ushort)0, parsed.CreditCharge, "Expected SMB 2.0.2 headers to preserve a reserved CreditCharge value of zero.");
                            TestAssertions.Equal((ushort)3, parsed.CreditRequest, "Unexpected SMB2 credit request value.");
                            TestAssertions.Equal(0UL, parsed.MessageId, "Unexpected SMB2 message identifier.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Headers",
                        caseId: "HeaderReadersRejectMalformedInputs",
                        displayName: "SMB header readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1Header.ReadFrom(new byte[31]),
                                "A truncated SMB1 header should fail to parse.");

                            Smb1Header invalidSmb1Header = CreateValidSmb1Header();
                            invalidSmb1Header.Flags = (Smb1HeaderFlags)0x01;
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb1HeaderValidator.Validate(invalidSmb1Header),
                                "Unsupported SMB1 flag bits should fail validation.");

                            byte[] invalidSmb2Bytes = CreateValidSmb2Header().ToByteArray();
                            invalidSmb2Bytes[4] = 0x20;
                            invalidSmb2Bytes[5] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2Header.ReadFrom(invalidSmb2Bytes),
                                "An SMB2 header with the wrong structure size should fail to parse.");

                            Smb2Header invalidSmb2Header = CreateValidSmb2Header();
                            invalidSmb2Header.NextCommand = 4;
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2HeaderValidator.Validate(invalidSmb2Header),
                                "A misaligned SMB2 next-command offset should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 compound-packet suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2CompoundSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Compound",
                displayName: "SMB2 compound packet framing",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Compound",
                        caseId: "CompoundPacketsRoundTripAndTrimImplementedPayloads",
                        displayName: "SMB2 compound packets round-trip with aligned offsets and trim implemented request or response payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Write, 0),
                                        new Smb2WriteRequest
                                        {
                                            Offset = 0,
                                            PersistentFileId = 11,
                                            VolatileFileId = 12,
                                            Channel = 0,
                                            RemainingBytes = 0,
                                            Flags = Smb2WriteFlags.None,
                                            DataBuffer = Encoding.ASCII.GetBytes("abc"),
                                            WriteChannelInfo = Array.Empty<byte>()
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Flush, 1),
                                        new Smb2FlushRequest
                                        {
                                            PersistentFileId = 11,
                                            VolatileFileId = 12
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 2),
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = 11,
                                            VolatileFileId = 12
                                        }.ToByteArray())
                                });
                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray());

                            TestAssertions.Equal(3, parsedRequestPacket.Entries.Count, "Unexpected SMB2 compound request entry count.");
                            TestAssertions.True(parsedRequestPacket.Entries[0].Header.NextCommand != 0, "Expected the first compounded request to point at a subsequent entry.");
                            TestAssertions.True((parsedRequestPacket.Entries[0].Header.NextCommand % 8) == 0, "Expected the first compounded request offset to remain 8-byte aligned.");
                            TestAssertions.True((parsedRequestPacket.Entries[1].Header.NextCommand % 8) == 0, "Expected the second compounded request offset to remain 8-byte aligned.");
                            TestAssertions.Equal(0U, parsedRequestPacket.Entries[2].Header.NextCommand, "Expected the final compounded request to terminate the chain.");

                            Smb2WriteRequest parsedWriteRequest = Smb2WriteRequest.ReadFrom(Smb2CompoundPayloadHelper.TrimRequestPayload(parsedRequestPacket.Entries[0].Header.Command, parsedRequestPacket.Entries[0].Payload));
                            Smb2FlushRequest parsedFlushRequest = Smb2FlushRequest.ReadFrom(Smb2CompoundPayloadHelper.TrimRequestPayload(parsedRequestPacket.Entries[1].Header.Command, parsedRequestPacket.Entries[1].Payload));
                            Smb2CloseRequest parsedCloseRequest = Smb2CloseRequest.ReadFrom(Smb2CompoundPayloadHelper.TrimRequestPayload(parsedRequestPacket.Entries[2].Header.Command, parsedRequestPacket.Entries[2].Payload));

                            TestAssertions.SequenceEqual(Encoding.ASCII.GetBytes("abc"), parsedWriteRequest.DataBuffer, "Unexpected compounded write payload.");
                            TestAssertions.Equal(12UL, parsedFlushRequest.VolatileFileId, "Unexpected compounded flush volatile file identifier.");
                            TestAssertions.Equal(11UL, parsedCloseRequest.PersistentFileId, "Unexpected compounded close persistent file identifier.");

                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Read, 0, flags: Smb2HeaderFlags.ServerToRedir),
                                        new Smb2ReadResponse
                                        {
                                            DataBuffer = Encoding.ASCII.GetBytes("payload"),
                                            DataRemaining = 0,
                                            Flags = 0
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1, flags: Smb2HeaderFlags.ServerToRedir),
                                        new Smb2CloseResponse
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            EndOfFile = 7,
                                            FileAttributes = ProtocolFileAttributes.Normal
                                        }.ToByteArray())
                                });
                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                            Smb2ReadResponse parsedReadResponse = Smb2ReadResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[0].Header.Command, parsedResponsePacket.Entries[0].Payload));
                            Smb2CloseResponse parsedCloseResponse = Smb2CloseResponse.ReadFrom(Smb2CompoundPayloadHelper.TrimResponsePayload(parsedResponsePacket.Entries[1].Header.Command, parsedResponsePacket.Entries[1].Payload));

                            TestAssertions.SequenceEqual(Encoding.ASCII.GetBytes("payload"), parsedReadResponse.DataBuffer, "Unexpected compounded read-response payload.");
                            TestAssertions.Equal(7UL, parsedCloseResponse.EndOfFile, "Unexpected compounded close-response EOF size.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Compound",
                        caseId: "CompoundPacketsRejectMalformedOffsetsAndPadding",
                        displayName: "SMB2 compound packets reject malformed next-command offsets and non-zero trailing padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CompoundPacket validPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Flush, 0),
                                        new Smb2FlushRequest
                                        {
                                            PersistentFileId = 1,
                                            VolatileFileId = 2
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1),
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = 1,
                                            VolatileFileId = 2
                                        }.ToByteArray())
                                });
                            byte[] malformedPacketBytes = validPacket.ToByteArray();
                            malformedPacketBytes[20] = 0x04;
                            malformedPacketBytes[21] = 0x00;
                            malformedPacketBytes[22] = 0x00;
                            malformedPacketBytes[23] = 0x00;

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CompoundPacket.ReadFrom(malformedPacketBytes),
                                "A compounded packet with a misaligned NextCommand value should fail to parse.");

                            byte[] readResponseBytes = new Smb2ReadResponse
                            {
                                DataBuffer = new byte[] { 0x01, 0x02, 0x03 },
                                DataRemaining = 0,
                                Flags = 0
                            }.ToByteArray();
                            byte[] invalidPaddedReadResponse = new byte[readResponseBytes.Length + 4];
                            Array.Copy(readResponseBytes, invalidPaddedReadResponse, readResponseBytes.Length);
                            invalidPaddedReadResponse[readResponseBytes.Length] = 0x7F;

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Read, invalidPaddedReadResponse),
                                "A compounded response payload with non-zero trailing padding should fail trimming.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Compound",
                        caseId: "CompoundPacketsPreserveRelatedOperationFlags",
                        displayName: "SMB2 compound packets preserve related-operation flags across aligned request and response headers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Create, 0),
                                        new Smb2CreateRequest
                                        {
                                            RequestedOplockLevel = Smb2OplockLevel.None,
                                            ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                            DesiredAccess = 0x0012019FU,
                                            FileAttributes = ProtocolFileAttributes.Normal,
                                            ShareAccess = 0x00000007U,
                                            CreateDisposition = Smb2CreateDisposition.OpenIf,
                                            CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                            Name = "compound.txt",
                                            CreateContexts = Array.Empty<byte>()
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1, flags: Smb2HeaderFlags.RelatedOperations),
                                        new Smb2CloseRequest
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            PersistentFileId = UInt64.MaxValue,
                                            VolatileFileId = UInt64.MaxValue
                                        }.ToByteArray())
                                });

                            Smb2CompoundPacket parsedRequestPacket = Smb2CompoundPacket.ReadFrom(requestPacket.ToByteArray());
                            TestAssertions.Equal(Smb2HeaderFlags.RelatedOperations, parsedRequestPacket.Entries[1].Header.Flags, "Expected the related-operation request flag to round-trip.");

                            Smb2CompoundPacket responsePacket = new Smb2CompoundPacket(
                                new List<Smb2CompoundPacketEntry>
                                {
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Create, 0, flags: Smb2HeaderFlags.ServerToRedir),
                                        new Smb2CreateResponse
                                        {
                                            OplockLevel = Smb2OplockLevel.None,
                                            Flags = 0,
                                            CreateAction = Smb2CreateAction.Opened,
                                            FileAttributes = ProtocolFileAttributes.Normal,
                                            PersistentFileId = 10,
                                            VolatileFileId = 11,
                                            CreateContexts = Array.Empty<byte>()
                                        }.ToByteArray()),
                                    new Smb2CompoundPacketEntry(
                                        CreateCompoundHeader(Smb2Command.Close, 1, flags: Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations),
                                        new Smb2CloseResponse
                                        {
                                            Flags = Smb2CloseFlags.None,
                                            FileAttributes = ProtocolFileAttributes.Normal
                                        }.ToByteArray())
                                });

                            Smb2CompoundPacket parsedResponsePacket = Smb2CompoundPacket.ReadFrom(responsePacket.ToByteArray());
                            TestAssertions.Equal(
                                Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.RelatedOperations,
                                parsedResponsePacket.Entries[1].Header.Flags,
                                "Expected the related-operation response flag to round-trip.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 negotiate-message suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2NegotiateSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Negotiate",
                displayName: "SMB2 negotiate messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Negotiate",
                        caseId: "Smb2NegotiateMessagesRoundTrip",
                        displayName: "SMB2 negotiate request and response bodies round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Guid clientGuid = new Guid("00112233-4455-6677-8899-aabbccddeeff");
                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.Dfs,
                                ClientGuid = clientGuid,
                                ClientStartTime = 0x0102030405060708UL,
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };

                            Smb2NegotiateRequestValidator.Validate(request);
                            byte[] encodedRequest = request.ToByteArray();
                            TestAssertions.Equal(40, encodedRequest.Length, "Unexpected SMB2 negotiate request length.");

                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(encodedRequest);
                            Smb2NegotiateRequestValidator.Validate(parsedRequest);
                            TestAssertions.Equal(clientGuid, parsedRequest.ClientGuid, "The SMB2 negotiate client GUID changed.");
                            TestAssertions.Equal(Smb2GlobalCapabilities.Dfs, parsedRequest.Capabilities, "The SMB2 negotiate request capabilities changed.");
                            TestAssertions.Equal(2, parsedRequest.Dialects.Length, "Unexpected SMB2 negotiate dialect count.");
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedRequest.Dialects[0], "Unexpected first SMB2 negotiate dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, parsedRequest.Dialects[1], "Unexpected second SMB2 negotiate dialect.");

                            byte[] negotiateContextData =
                            {
                                0x01, 0x00, 0x0A, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
                            };
                            Smb2NegotiateRequest smb311ShapeRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.LargeMtu | Smb2GlobalCapabilities.Encryption,
                                ClientGuid = clientGuid,
                                Dialects = new SmbDialect[] { SmbDialect.Smb21, SmbDialect.Smb302, SmbDialect.Smb311 },
                                NegotiateContextCount = 1,
                                NegotiateContextData = negotiateContextData
                            };

                            byte[] encodedSmb311ShapeRequest = smb311ShapeRequest.ToByteArray();
                            Smb2NegotiateRequest parsedSmb311ShapeRequest = Smb2NegotiateRequest.ReadFrom(encodedSmb311ShapeRequest);
                            TestAssertions.Equal(64, encodedSmb311ShapeRequest.Length, "Unexpected SMB 3.1.1-style negotiate request length.");
                            TestAssertions.Equal((uint)112, parsedSmb311ShapeRequest.NegotiateContextOffset, "Unexpected SMB 3.1.1-style negotiate context offset.");
                            TestAssertions.Equal((ushort)1, parsedSmb311ShapeRequest.NegotiateContextCount, "Unexpected SMB 3.1.1-style negotiate context count.");
                            TestAssertions.Equal(SmbDialect.Smb311, parsedSmb311ShapeRequest.Dialects[2], "Expected the parser to preserve the SMB 3.1.1 dialect offer.");
                            TestAssertions.SequenceEqual(
                                negotiateContextData,
                                parsedSmb311ShapeRequest.NegotiateContextData,
                                "Expected the parser to preserve raw SMB 3.1.1-style negotiate context bytes.");

                            byte[] extendedRequest = new byte[encodedRequest.Length + 8];
                            Buffer.BlockCopy(encodedRequest, 0, extendedRequest, 0, encodedRequest.Length);
                            Buffer.BlockCopy(new byte[] { 0x44, 0x33, 0x22, 0x11, 0x02, 0x00, 0x00, 0x00 }, 0, extendedRequest, encodedRequest.Length, 8);
                            Smb2NegotiateRequest parsedExtendedRequest = Smb2NegotiateRequest.ReadFrom(extendedRequest);
                            byte[] trimmedExtendedRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Negotiate, extendedRequest);
                            TestAssertions.Equal(extendedRequest.Length, trimmedExtendedRequest.Length, "Expected negotiate trimming to preserve trailing dialect-context bytes.");
                            TestAssertions.Equal(2, parsedExtendedRequest.Dialects.Length, "Unexpected extended SMB2 negotiate dialect count.");
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedExtendedRequest.Dialects[0], "Unexpected first extended SMB2 negotiate dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, parsedExtendedRequest.Dialects[1], "Unexpected second extended SMB2 negotiate dialect.");

                            Guid serverGuid = new Guid("10213243-5465-7687-98a9-bacbdcedfe0f");
                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb2002,
                                ServerGuid = serverGuid,
                                Capabilities = Smb2GlobalCapabilities.None,
                                MaxTransactSize = 65536,
                                MaxReadSize = 131072,
                                MaxWriteSize = 196608,
                                SystemTime = 0x1122334455667788UL,
                                ServerStartTime = 0x0101010101010101UL,
                                SecurityBuffer = Array.Empty<byte>()
                            };

                            Smb2NegotiateResponseValidator.Validate(response);
                            byte[] encodedResponse = response.ToByteArray();
                            TestAssertions.Equal(64, encodedResponse.Length, "Unexpected SMB2 negotiate response length.");

                            Smb2NegotiateResponse parsedResponse = Smb2NegotiateResponse.ReadFrom(encodedResponse);
                            Smb2NegotiateResponseValidator.Validate(parsedResponse);
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedResponse.Dialect, "The SMB2 negotiate response dialect changed.");
                            TestAssertions.Equal(serverGuid, parsedResponse.ServerGuid, "The SMB2 negotiate server GUID changed.");
                            TestAssertions.Equal((uint)65536, parsedResponse.MaxTransactSize, "The SMB2 negotiate max transact size changed.");
                            TestAssertions.Equal((uint)131072, parsedResponse.MaxReadSize, "The SMB2 negotiate max read size changed.");
                            TestAssertions.Equal((uint)196608, parsedResponse.MaxWriteSize, "The SMB2 negotiate max write size changed.");
                            TestAssertions.Equal(0, parsedResponse.SecurityBuffer.Length, "The SMB2 negotiate security buffer should be empty in this vector.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Negotiate",
                        caseId: "Smb1MultiProtocolNegotiateRoundTrips",
                        displayName: "SMB1 multi-protocol negotiate requests round-trip and expose SMB2 bootstrap dialects",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1NegotiateRequest request = new Smb1NegotiateRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Negotiate,
                                    Flags = Smb1HeaderFlags.CanonicalizedPaths | Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.LongNames | Smb1HeaderFlags2.Unicode,
                                    ProcessIdHigh = 0x1122,
                                    ProcessIdLow = 0x3344,
                                    MultiplexId = 7
                                },
                                Dialects = new string[]
                                {
                                    "NT LM 0.12",
                                    Smb1NegotiateRequest.Smb2002DialectString,
                                    Smb1NegotiateRequest.Smb2WildcardDialectString
                                }
                            };

                            byte[] encodedRequest = request.ToByteArray();
                            Smb1NegotiateRequest parsedRequest = Smb1NegotiateRequest.ReadFrom(encodedRequest);

                            TestAssertions.Equal(Smb1Command.Negotiate, parsedRequest.Header.Command, "Unexpected SMB1 negotiate command.");
                            TestAssertions.Equal(3, parsedRequest.Dialects.Length, "Unexpected SMB1 negotiate dialect count.");
                            TestAssertions.Equal("NT LM 0.12", parsedRequest.Dialects[0], "Unexpected first SMB1 negotiate dialect.");
                            TestAssertions.True(parsedRequest.ContainsDialect(Smb1NegotiateRequest.Smb2002DialectString), "Expected SMB 2.002 to be present in the multi-protocol dialect list.");
                            TestAssertions.True(parsedRequest.ContainsDialect(Smb1NegotiateRequest.Smb2WildcardDialectString), "Expected SMB 2.??? to be present in the multi-protocol dialect list.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Negotiate",
                        caseId: "Smb2NegotiateMessagesRejectMalformedInputs",
                        displayName: "SMB2 negotiate message codecs and validators reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                ClientGuid = new Guid("00112233-4455-6677-8899-aabbccddeeff"),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };
                            byte[] invalidRequestBytes = request.ToByteArray();
                            invalidRequestBytes[0] = 0x00;
                            invalidRequestBytes[1] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(invalidRequestBytes),
                                "An SMB2 negotiate request with the wrong structure size should fail to parse.");

                            Smb1NegotiateRequest smb1Request = new Smb1NegotiateRequest
                            {
                                Dialects = new string[]
                                {
                                    "NT LM 0.12",
                                    Smb1NegotiateRequest.Smb2002DialectString
                                }
                            };
                            int smb1HeaderLength = new Smb1Header().ToByteArray().Length;
                            byte[] invalidSmb1WordCountBytes = smb1Request.ToByteArray();
                            invalidSmb1WordCountBytes[smb1HeaderLength] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NegotiateRequest.ReadFrom(invalidSmb1WordCountBytes),
                                "An SMB1 multi-protocol negotiate request with a non-zero WordCount should fail to parse.");

                            byte[] invalidSmb1DialectFormatBytes = smb1Request.ToByteArray();
                            invalidSmb1DialectFormatBytes[smb1HeaderLength + 3] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NegotiateRequest.ReadFrom(invalidSmb1DialectFormatBytes),
                                "An SMB1 multi-protocol negotiate request with an invalid dialect buffer format should fail to parse.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => new Smb1NegotiateRequest
                                {
                                    Header = new Smb1Header
                                    {
                                        Command = Smb1Command.Echo
                                    },
                                    Dialects = new string[]
                                    {
                                        Smb1NegotiateRequest.Smb2002DialectString
                                    }
                                }.ToByteArray(),
                                "Only SMB_COM_NEGOTIATE headers should serialize through the SMB1 multi-protocol negotiate codec.");

                            byte[] unknownDialectBytes = request.ToByteArray();
                            unknownDialectBytes[38] = 0xFF;
                            unknownDialectBytes[39] = 0xFF;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(unknownDialectBytes),
                                "An SMB2 negotiate request with an unknown dialect should fail to parse.");

                            Smb2NegotiateRequest smb311ShapeRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Capabilities = Smb2GlobalCapabilities.Encryption,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new SmbDialect[] { SmbDialect.Smb302, SmbDialect.Smb311 },
                                NegotiateContextCount = 1,
                                NegotiateContextData = new byte[]
                                {
                                    0x01, 0x00, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD
                                }
                            };
                            byte[] malformedContextOffsetBytes = smb311ShapeRequest.ToByteArray();
                            Buffer.BlockCopy(new byte[] { 0x50, 0x00, 0x00, 0x00 }, 0, malformedContextOffsetBytes, 28, 4);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(malformedContextOffsetBytes),
                                "An SMB 3.1.1-style negotiate request with a body-relative or too-small negotiate context offset should fail to parse.");

                            Smb2NegotiateRequest duplicateDialectRequest = new Smb2NegotiateRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                ClientGuid = Guid.NewGuid(),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb2002 }
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2NegotiateRequestValidator.Validate(duplicateDialectRequest),
                                "Duplicate SMB2 negotiate dialects should fail validation.");

                            Smb2NegotiateResponse invalidSecurityModeResponse = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningRequired,
                                Dialect = SmbDialect.Smb2002,
                                ServerGuid = Guid.NewGuid(),
                                MaxTransactSize = 1,
                                MaxReadSize = 1,
                                MaxWriteSize = 1
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2NegotiateResponseValidator.Validate(invalidSecurityModeResponse),
                                "SigningRequired without SigningEnabled should fail validation.");

                            Smb2NegotiateResponse responseWithSecurityBuffer = new Smb2NegotiateResponse
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb2002,
                                ServerGuid = Guid.NewGuid(),
                                MaxTransactSize = 1,
                                MaxReadSize = 1,
                                MaxWriteSize = 1,
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            byte[] invalidResponseBytes = responseWithSecurityBuffer.ToByteArray();
                            invalidResponseBytes[56] = 0x7F;
                            invalidResponseBytes[57] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateResponse.ReadFrom(invalidResponseBytes),
                                "An SMB2 negotiate response with an invalid security-buffer offset should fail to parse.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the bounded SMB1 NEGOTIATE response codec suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb1NegotiateResponseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb1Negotiate",
                displayName: "Bounded SMB1 NEGOTIATE response codec",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NegotiateResponseRoundTripsExtendedSecurityShape",
                        displayName: "Bounded SMB1 NEGOTIATE response round-trips the NT LM 0.12 extended-security shape",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] securityBlob = new byte[]
                            {
                                0x60, 0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
                                0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C
                            };

                            Smb1NegotiateResponse response = new Smb1NegotiateResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Negotiate,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    ProcessIdHigh = 0,
                                    Signature = new byte[8],
                                    TreeId = 0,
                                    ProcessIdLow = 0xFEED,
                                    UserId = 0,
                                    MultiplexId = 0x1234
                                },
                                DialectIndex = 5,
                                SecurityMode = Smb1SecurityMode.UserSecurity | Smb1SecurityMode.EncryptPasswords | Smb1SecurityMode.SigningEnabled | Smb1SecurityMode.SigningRequired,
                                MaxMpxCount = 50,
                                MaxNumberVcs = 1,
                                MaxBufferSize = 65535,
                                MaxRawSize = 65536,
                                SessionKey = 0xDEADBEEFU,
                                Capabilities = Smb1Capabilities.Unicode | Smb1Capabilities.LargeFiles | Smb1Capabilities.NtSmbs | Smb1Capabilities.RpcRemoteApis | Smb1Capabilities.Status32 | Smb1Capabilities.NtFind | Smb1Capabilities.LargeReadX | Smb1Capabilities.LargeWriteX | Smb1Capabilities.ExtendedSecurity,
                                SystemTime = 0x01D811223344AABBUL,
                                ServerTimeZoneMinutes = -480,
                                ServerGuid = Guid.Parse("0F11D8A6-3344-4F2C-8FB0-1A6E6F7B9C50"),
                                SecurityBlob = securityBlob
                            };

                            byte[] wireBytes = response.ToByteArray();
                            Smb1NegotiateResponse parsed = Smb1NegotiateResponse.ReadFrom(wireBytes);

                            TestAssertions.Equal(response.DialectIndex, parsed.DialectIndex, "Unexpected SMB1 dialect index after round-trip.");
                            TestAssertions.Equal(response.SecurityMode, parsed.SecurityMode, "Unexpected SMB1 security mode after round-trip.");
                            TestAssertions.Equal(response.MaxMpxCount, parsed.MaxMpxCount, "Unexpected SMB1 MaxMpxCount after round-trip.");
                            TestAssertions.Equal(response.MaxNumberVcs, parsed.MaxNumberVcs, "Unexpected SMB1 MaxNumberVcs after round-trip.");
                            TestAssertions.Equal(response.MaxBufferSize, parsed.MaxBufferSize, "Unexpected SMB1 MaxBufferSize after round-trip.");
                            TestAssertions.Equal(response.MaxRawSize, parsed.MaxRawSize, "Unexpected SMB1 MaxRawSize after round-trip.");
                            TestAssertions.Equal(response.SessionKey, parsed.SessionKey, "Unexpected SMB1 SessionKey after round-trip.");
                            TestAssertions.Equal(response.Capabilities, parsed.Capabilities, "Unexpected SMB1 capability flags after round-trip.");
                            TestAssertions.Equal(response.SystemTime, parsed.SystemTime, "Unexpected SMB1 SystemTime after round-trip.");
                            TestAssertions.Equal(response.ServerTimeZoneMinutes, parsed.ServerTimeZoneMinutes, "Unexpected SMB1 server time-zone minutes after round-trip.");
                            TestAssertions.Equal(response.ServerGuid, parsed.ServerGuid, "Unexpected SMB1 server GUID after round-trip.");
                            TestAssertions.SequenceEqual(securityBlob, parsed.SecurityBlob, "Unexpected SMB1 SPNEGO security blob after round-trip.");

                            TestAssertions.Equal(Smb1DialectStrings.NtLm012, "NT LM 0.12", "Unexpected NT LM 0.12 dialect string constant.");
                            TestAssertions.Equal(Smb1DialectStrings.LanMan10, "LANMAN1.0", "Unexpected LANMAN1.0 dialect string constant.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1SessionSetupAndXRequestRoundTripsExtendedSecurityShape",
                        displayName: "Bounded SMB1 SESSION_SETUP_ANDX request round-trips the Unicode extended-security shape",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] securityBlob = new byte[]
                            {
                                0x60, 0x82, 0x01, 0x47, 0x06, 0x06, 0x2B, 0x06,
                                0x01, 0x05, 0x05, 0x02, 0xA0, 0x82, 0x01
                            };

                            Smb1SessionSetupAndXRequest request = new Smb1SessionSetupAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.SessionSetupAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    ProcessIdHigh = 0,
                                    Signature = new byte[8],
                                    TreeId = 0,
                                    ProcessIdLow = 0xCAFE,
                                    UserId = 0,
                                    MultiplexId = 0x4242
                                },
                                MaxBufferSize = 4356,
                                MaxMpxCount = 50,
                                VcNumber = 0,
                                SessionKey = 0xDEADBEEFU,
                                Capabilities = Smb1Capabilities.Unicode | Smb1Capabilities.LargeFiles | Smb1Capabilities.NtSmbs | Smb1Capabilities.Status32 | Smb1Capabilities.ExtendedSecurity,
                                SecurityBlob = securityBlob,
                                NativeOS = "Windows 11",
                                NativeLanMan = "OpenCIFS"
                            };

                            byte[] wireBytes = request.ToByteArray();
                            Smb1SessionSetupAndXRequest parsed = Smb1SessionSetupAndXRequest.ReadFrom(wireBytes);
                            TestAssertions.Equal(request.MaxBufferSize, parsed.MaxBufferSize, "Unexpected MaxBufferSize after round-trip.");
                            TestAssertions.Equal(request.MaxMpxCount, parsed.MaxMpxCount, "Unexpected MaxMpxCount after round-trip.");
                            TestAssertions.Equal(request.VcNumber, parsed.VcNumber, "Unexpected VcNumber after round-trip.");
                            TestAssertions.Equal(request.SessionKey, parsed.SessionKey, "Unexpected SessionKey after round-trip.");
                            TestAssertions.Equal(request.Capabilities, parsed.Capabilities, "Unexpected client capabilities after round-trip.");
                            TestAssertions.SequenceEqual(securityBlob, parsed.SecurityBlob, "Unexpected SPNEGO blob after round-trip.");
                            TestAssertions.Equal("Windows 11", parsed.NativeOS, "Unexpected NativeOS after round-trip.");
                            TestAssertions.Equal("OpenCIFS", parsed.NativeLanMan, "Unexpected NativeLanMan after round-trip.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1SessionSetupAndXResponseRoundTripsExtendedSecurityShapeAndPreservesGuestActionBit",
                        displayName: "Bounded SMB1 SESSION_SETUP_ANDX response round-trips the extended-security shape and preserves the guest action bit",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] securityBlob = new byte[]
                            {
                                0xA1, 0x1A, 0x30, 0x18, 0xA0, 0x03, 0x0A, 0x01,
                                0x00, 0xA1, 0x0B
                            };

                            Smb1SessionSetupAndXResponse response = new Smb1SessionSetupAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.SessionSetupAndX,
                                    Status = NtStatus.MoreProcessingRequired,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Action = Smb1SessionSetupAndXResponse.GuestLogonActionBit,
                                SecurityBlob = securityBlob,
                                NativeOS = "OpenCIFS",
                                NativeLanMan = "OpenCIFS",
                                PrimaryDomain = "WORKGROUP"
                            };

                            byte[] wireBytes = response.ToByteArray();
                            Smb1SessionSetupAndXResponse parsed = Smb1SessionSetupAndXResponse.ReadFrom(wireBytes);
                            TestAssertions.Equal(Smb1SessionSetupAndXResponse.GuestLogonActionBit, parsed.Action, "Unexpected SMB1 SESSION_SETUP_ANDX response action flags.");
                            TestAssertions.True(parsed.IsGuestLogon, "Expected the response to indicate a guest logon.");
                            TestAssertions.SequenceEqual(securityBlob, parsed.SecurityBlob, "Unexpected SPNEGO response blob after round-trip.");
                            TestAssertions.Equal("OpenCIFS", parsed.NativeOS, "Unexpected NativeOS after round-trip.");
                            TestAssertions.Equal("OpenCIFS", parsed.NativeLanMan, "Unexpected NativeLanMan after round-trip.");
                            TestAssertions.Equal("WORKGROUP", parsed.PrimaryDomain, "Unexpected PrimaryDomain after round-trip.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TreeConnectAndXRequestAndResponseRoundTripUnicodePathAndAsciiServiceShapes",
                        displayName: "Bounded SMB1 TREE_CONNECT_ANDX request and response round-trip Unicode path and ASCII service shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1TreeConnectAndXRequest request = new Smb1TreeConnectAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TreeConnectAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x0BAD,
                                    MultiplexId = 0x0123
                                },
                                Flags = 0,
                                Password = new byte[] { 0x00 },
                                Path = "\\\\fileserver.contoso.test\\share",
                                Service = "?????"
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1TreeConnectAndXRequest parsedRequest = Smb1TreeConnectAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.SequenceEqual(request.Password, parsedRequest.Password, "Unexpected SMB1 TREE_CONNECT_ANDX password after round-trip.");
                            TestAssertions.Equal(request.Path, parsedRequest.Path, "Unexpected SMB1 TREE_CONNECT_ANDX share path after round-trip.");
                            TestAssertions.Equal(request.Service, parsedRequest.Service, "Unexpected SMB1 TREE_CONNECT_ANDX service after round-trip.");

                            Smb1TreeConnectAndXResponse response = new Smb1TreeConnectAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TreeConnectAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xABCD,
                                    UserId = 0x0BAD,
                                    MultiplexId = 0x0123
                                },
                                OptionalSupport = 0x0001,
                                MaximalShareAccessRights = 0x001F01FFU,
                                GuestMaximalShareAccessRights = 0x00120089U,
                                Service = "A:",
                                NativeFileSystem = "NTFS"
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1TreeConnectAndXResponse parsedResponse = Smb1TreeConnectAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.OptionalSupport, parsedResponse.OptionalSupport, "Unexpected SMB1 TREE_CONNECT_ANDX optional-support flags.");
                            TestAssertions.Equal(response.MaximalShareAccessRights, parsedResponse.MaximalShareAccessRights, "Unexpected SMB1 TREE_CONNECT_ANDX maximal share access rights.");
                            TestAssertions.Equal(response.GuestMaximalShareAccessRights, parsedResponse.GuestMaximalShareAccessRights, "Unexpected SMB1 TREE_CONNECT_ANDX guest share access rights.");
                            TestAssertions.Equal(response.Service, parsedResponse.Service, "Unexpected SMB1 TREE_CONNECT_ANDX echoed service.");
                            TestAssertions.Equal(response.NativeFileSystem, parsedResponse.NativeFileSystem, "Unexpected SMB1 TREE_CONNECT_ANDX NativeFileSystem.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1LogoffAndXRoundTripsAndRejectsNonZeroByteCount",
                        displayName: "Bounded SMB1 LOGOFF_ANDX round-trips and rejects non-zero ByteCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1LogoffAndX message = new Smb1LogoffAndX
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.LogoffAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                AndXCommand = 0xFF,
                                AndXOffset = 0
                            };

                            byte[] wireBytes = message.ToByteArray();
                            Smb1LogoffAndX parsed = Smb1LogoffAndX.ReadFrom(wireBytes);
                            TestAssertions.Equal((byte)0xFF, parsed.AndXCommand, "Unexpected SMB1 LOGOFF_ANDX AndX command.");
                            TestAssertions.Equal((ushort)0, parsed.AndXOffset, "Unexpected SMB1 LOGOFF_ANDX AndX offset.");

                            byte[] tampered = (byte[])wireBytes.Clone();
                            tampered[tampered.Length - 1] = 0x01;
                            tampered[tampered.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1LogoffAndX.ReadFrom(tampered),
                                "SMB1 LOGOFF_ANDX should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TreeDisconnectRoundTripsAndRejectsNonZeroByteCount",
                        displayName: "Bounded SMB1 TREE_DISCONNECT round-trips and rejects non-zero ByteCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1TreeDisconnect message = new Smb1TreeDisconnect
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.TreeDisconnect,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                }
                            };

                            byte[] wireBytes = message.ToByteArray();
                            Smb1TreeDisconnect parsed = Smb1TreeDisconnect.ReadFrom(wireBytes);
                            TestAssertions.Equal((ushort)0xCAFE, parsed.Header.TreeId, "Unexpected SMB1 TREE_DISCONNECT TreeId after round-trip.");

                            byte[] tamperedDisconnect = (byte[])wireBytes.Clone();
                            tamperedDisconnect[tamperedDisconnect.Length - 1] = 0x05;
                            tamperedDisconnect[tamperedDisconnect.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1TreeDisconnect.ReadFrom(tamperedDisconnect),
                                "SMB1 TREE_DISCONNECT should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1CloseRequestAndResponseRoundTripFidAndRejectsMalformedShapes",
                        displayName: "Bounded SMB1 CLOSE request and response round-trip FID/LastWriteTime and reject malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1CloseRequest request = new Smb1CloseRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Close,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                LastWriteTime = 0x68001000U
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1CloseRequest parsedRequest = Smb1CloseRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 CLOSE FileId after round-trip.");
                            TestAssertions.Equal(request.LastWriteTime, parsedRequest.LastWriteTime, "Unexpected SMB1 CLOSE LastWriteTime after round-trip.");

                            byte[] tamperedRequest = (byte[])requestBytes.Clone();
                            tamperedRequest[tamperedRequest.Length - 1] = 0x01;
                            tamperedRequest[tamperedRequest.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1CloseRequest.ReadFrom(tamperedRequest),
                                "SMB1 CLOSE request should reject non-zero ByteCount payloads.");

                            Smb1CloseResponse response = new Smb1CloseResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Close,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                }
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1CloseResponse parsedResponse = Smb1CloseResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal((ushort)0x4242, parsedResponse.Header.MultiplexId, "Unexpected SMB1 CLOSE response MultiplexId.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x01;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1CloseResponse.ReadFrom(tamperedResponse),
                                "SMB1 CLOSE response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1EchoRequestAndResponseRoundTripPayloadAndRejectByteCountMismatch",
                        displayName: "Bounded SMB1 ECHO request and response round-trip payload and reject ByteCount mismatch",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] payload = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

                            Smb1EchoRequest request = new Smb1EchoRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Echo,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                EchoCount = 3,
                                Data = payload
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1EchoRequest parsedRequest = Smb1EchoRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal((ushort)3, parsedRequest.EchoCount, "Unexpected SMB1 ECHO EchoCount after round-trip.");
                            TestAssertions.SequenceEqual(payload, parsedRequest.Data, "Unexpected SMB1 ECHO request payload after round-trip.");

                            byte[] tamperedEchoRequest = (byte[])requestBytes.Clone();
                            int byteCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + sizeof(ushort);
                            tamperedEchoRequest[byteCountIndex] = 0xFF;
                            tamperedEchoRequest[byteCountIndex + 1] = 0xFF;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1EchoRequest.ReadFrom(tamperedEchoRequest),
                                "SMB1 ECHO request should reject ByteCount that exceeds the buffer.");

                            Smb1EchoResponse response = new Smb1EchoResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Echo,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                SequenceNumber = 2,
                                Data = payload
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1EchoResponse parsedResponse = Smb1EchoResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal((ushort)2, parsedResponse.SequenceNumber, "Unexpected SMB1 ECHO SequenceNumber after round-trip.");
                            TestAssertions.SequenceEqual(payload, parsedResponse.Data, "Unexpected SMB1 ECHO response payload after round-trip.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NtCreateAndXRequestAndResponseRoundTripUnicodeFileNameAndExtendedFields",
                        displayName: "Bounded SMB1 NT_CREATE_ANDX request and response round-trip Unicode file name and extended fields",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1NtCreateAndXRequest request = new Smb1NtCreateAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtCreateAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Flags = 0x16,
                                RootDirectoryFileId = 0,
                                DesiredAccess = 0x00120089U,
                                AllocationSize = 0,
                                ExtFileAttributes = 0x00000020U,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = 0x00000001U,
                                CreateOptions = 0x00000040U,
                                ImpersonationLevel = 0x00000002U,
                                SecurityFlags = 0x03,
                                FileName = "docs\\readme.txt"
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1NtCreateAndXRequest parsedRequest = Smb1NtCreateAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.DesiredAccess, parsedRequest.DesiredAccess, "Unexpected SMB1 NT_CREATE_ANDX DesiredAccess after round-trip.");
                            TestAssertions.Equal(request.CreateDisposition, parsedRequest.CreateDisposition, "Unexpected SMB1 NT_CREATE_ANDX CreateDisposition after round-trip.");
                            TestAssertions.Equal(request.CreateOptions, parsedRequest.CreateOptions, "Unexpected SMB1 NT_CREATE_ANDX CreateOptions after round-trip.");
                            TestAssertions.Equal(request.SecurityFlags, parsedRequest.SecurityFlags, "Unexpected SMB1 NT_CREATE_ANDX SecurityFlags after round-trip.");
                            TestAssertions.Equal(request.FileName, parsedRequest.FileName, "Unexpected SMB1 NT_CREATE_ANDX FileName after round-trip.");

                            Smb1NtCreateAndXResponse response = new Smb1NtCreateAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtCreateAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                OplockLevel = 2,
                                FileId = 0x4242,
                                CreateDisposition = 1,
                                CreateTime = 0x01D89AB000000000L,
                                LastAccessTime = 0x01D89AB000000001L,
                                LastWriteTime = 0x01D89AB000000002L,
                                LastChangeTime = 0x01D89AB000000003L,
                                ExtFileAttributes = 0x00000020U,
                                AllocationSize = 4096L,
                                EndOfFile = 1234L,
                                ResourceType = 1,
                                NMPipeStatus = 0,
                                Directory = 0
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1NtCreateAndXResponse parsedResponse = Smb1NtCreateAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.FileId, parsedResponse.FileId, "Unexpected SMB1 NT_CREATE_ANDX response FileId.");
                            TestAssertions.Equal(response.OplockLevel, parsedResponse.OplockLevel, "Unexpected SMB1 NT_CREATE_ANDX response OplockLevel.");
                            TestAssertions.Equal(response.EndOfFile, parsedResponse.EndOfFile, "Unexpected SMB1 NT_CREATE_ANDX response EndOfFile.");
                            TestAssertions.Equal(response.AllocationSize, parsedResponse.AllocationSize, "Unexpected SMB1 NT_CREATE_ANDX response AllocationSize.");
                            TestAssertions.Equal(response.LastWriteTime, parsedResponse.LastWriteTime, "Unexpected SMB1 NT_CREATE_ANDX response LastWriteTime.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x01;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NtCreateAndXResponse.ReadFrom(tamperedResponse),
                                "SMB1 NT_CREATE_ANDX response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1ReadAndXRequestAndResponseRoundTrip64BitOffsetAndDataPayload",
                        displayName: "Bounded SMB1 READ_ANDX request and response round-trip 64-bit offset and data payload",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1ReadAndXRequest request = new Smb1ReadAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.ReadAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                FileOffset = 0x0000_0001_0000_0010UL,
                                MaxCountOfBytesToReturn = 4096,
                                MinCountOfBytesToReturn = 1,
                                TimeoutOrMaxCountHigh = 0xFFFFFFFFU,
                                Remaining = 0
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1ReadAndXRequest parsedRequest = Smb1ReadAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 READ_ANDX FileId after round-trip.");
                            TestAssertions.Equal(request.FileOffset, parsedRequest.FileOffset, "Unexpected SMB1 READ_ANDX 64-bit offset after round-trip.");
                            TestAssertions.Equal(request.MaxCountOfBytesToReturn, parsedRequest.MaxCountOfBytesToReturn, "Unexpected SMB1 READ_ANDX MaxCount after round-trip.");

                            byte[] tamperedRequest = (byte[])requestBytes.Clone();
                            tamperedRequest[tamperedRequest.Length - 1] = 0x05;
                            tamperedRequest[tamperedRequest.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1ReadAndXRequest.ReadFrom(tamperedRequest),
                                "SMB1 READ_ANDX request should reject non-zero ByteCount payloads.");

                            byte[] payload = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };

                            Smb1ReadAndXResponse response = new Smb1ReadAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.ReadAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Available = 0xFFFF,
                                Data = payload
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1ReadAndXResponse parsedResponse = Smb1ReadAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.Available, parsedResponse.Available, "Unexpected SMB1 READ_ANDX response Available.");
                            TestAssertions.SequenceEqual(payload, parsedResponse.Data, "Unexpected SMB1 READ_ANDX response payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1WriteAndXRequestAndResponseRoundTripDataPayloadAndRejectMalformedShapes",
                        displayName: "Bounded SMB1 WRITE_ANDX request and response round-trip data payload and reject malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] payload = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

                            Smb1WriteAndXRequest request = new Smb1WriteAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.WriteAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                FileOffset = 0x0000_0002_0000_0030UL,
                                WriteMode = 0x0008,
                                Remaining = 0,
                                Data = payload
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb1WriteAndXRequest parsedRequest = Smb1WriteAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 WRITE_ANDX FileId after round-trip.");
                            TestAssertions.Equal(request.FileOffset, parsedRequest.FileOffset, "Unexpected SMB1 WRITE_ANDX 64-bit offset after round-trip.");
                            TestAssertions.Equal(request.WriteMode, parsedRequest.WriteMode, "Unexpected SMB1 WRITE_ANDX WriteMode after round-trip.");
                            TestAssertions.SequenceEqual(payload, parsedRequest.Data, "Unexpected SMB1 WRITE_ANDX request payload after round-trip.");

                            Smb1WriteAndXResponse response = new Smb1WriteAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.WriteAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                Count = (ushort)payload.Length,
                                Available = 0xFFFF,
                                CountHigh = 0
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1WriteAndXResponse parsedResponse = Smb1WriteAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.Count, parsedResponse.Count, "Unexpected SMB1 WRITE_ANDX response Count.");
                            TestAssertions.Equal(response.Available, parsedResponse.Available, "Unexpected SMB1 WRITE_ANDX response Available.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x05;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1WriteAndXResponse.ReadFrom(tamperedResponse),
                                "SMB1 WRITE_ANDX response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1LockingAndXRequestAndResponseRoundTripLargeFileLockRangesAndRejectMalformedShapes",
                        displayName: "Bounded SMB1 LOCKING_ANDX request and response round-trip large-file lock ranges and reject malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb1LockingAndXRequest request = new Smb1LockingAndXRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.LockingAndX,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                FileId = 0x4242,
                                LockType = Smb1LockingAndXRequest.LockTypeLargeFiles,
                                OplockLevel = 0,
                                Timeout = 5000
                            };
                            request.Locks.Add(new Smb1LockingAndXRequest.LockRange
                            {
                                ProcessId = 0x0042,
                                Offset = 0x0000_0001_0000_0010UL,
                                Length = 0x0000_0000_0000_1000UL
                            });
                            request.Unlocks.Add(new Smb1LockingAndXRequest.LockRange
                            {
                                ProcessId = 0x0042,
                                Offset = 0x0000_0002_0000_0000UL,
                                Length = 0x0000_0000_0000_2000UL
                            });

                            byte[] requestBytes = request.ToByteArray();
                            Smb1LockingAndXRequest parsedRequest = Smb1LockingAndXRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.FileId, parsedRequest.FileId, "Unexpected SMB1 LOCKING_ANDX FileId after round-trip.");
                            TestAssertions.Equal(request.LockType, parsedRequest.LockType, "Unexpected SMB1 LOCKING_ANDX LockType after round-trip.");
                            TestAssertions.Equal(request.Timeout, parsedRequest.Timeout, "Unexpected SMB1 LOCKING_ANDX Timeout after round-trip.");
                            TestAssertions.Equal(1, parsedRequest.Locks.Count, "Unexpected SMB1 LOCKING_ANDX Locks count.");
                            TestAssertions.Equal(1, parsedRequest.Unlocks.Count, "Unexpected SMB1 LOCKING_ANDX Unlocks count.");
                            TestAssertions.Equal(request.Locks[0].Offset, parsedRequest.Locks[0].Offset, "Unexpected SMB1 LOCKING_ANDX lock offset after round-trip.");
                            TestAssertions.Equal(request.Locks[0].Length, parsedRequest.Locks[0].Length, "Unexpected SMB1 LOCKING_ANDX lock length after round-trip.");
                            TestAssertions.Equal(request.Unlocks[0].Offset, parsedRequest.Unlocks[0].Offset, "Unexpected SMB1 LOCKING_ANDX unlock offset after round-trip.");

                            byte[] tamperedRequest = (byte[])requestBytes.Clone();
                            tamperedRequest[ProtocolConstants.Smb1HeaderLength + 1 + (Smb1LockingAndXRequest.LockTypeOplockRelease * 0)] = 0x05;
                            int byteCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (8 * sizeof(ushort));
                            tamperedRequest[byteCountIndex] = 0x10;
                            tamperedRequest[byteCountIndex + 1] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1LockingAndXRequest.ReadFrom(tamperedRequest),
                                "SMB1 LOCKING_ANDX request should reject ByteCount mismatched with declared lock counts.");

                            Smb1LockingAndXResponse response = new Smb1LockingAndXResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.LockingAndX,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                }
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb1LockingAndXResponse parsedResponse = Smb1LockingAndXResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal((ushort)0x4242, parsedResponse.Header.MultiplexId, "Unexpected SMB1 LOCKING_ANDX response MultiplexId.");

                            byte[] tamperedResponse = (byte[])responseBytes.Clone();
                            tamperedResponse[tamperedResponse.Length - 1] = 0x01;
                            tamperedResponse[tamperedResponse.Length - 2] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1LockingAndXResponse.ReadFrom(tamperedResponse),
                                "SMB1 LOCKING_ANDX response should reject non-zero ByteCount payloads.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "NetBiosSessionRequestRoundTripsCalledAndCallingNamesAndRejectsMalformedShapes",
                        displayName: "Bounded NetBIOS SESSION_REQUEST round-trips called/calling names and rejects malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NetBiosEncodedName called = NetBiosEncodedName.FromServiceName("FILESERVER", NetBiosEncodedName.FileServerServiceSuffix);
                            NetBiosEncodedName calling = NetBiosEncodedName.FromServiceName("WORKSTATION", NetBiosEncodedName.WorkstationServiceSuffix);

                            NetBiosSessionRequest request = new NetBiosSessionRequest
                            {
                                CalledName = called,
                                CallingName = calling
                            };

                            byte[] wireBytes = request.ToByteArray();
                            TestAssertions.Equal(NetBiosSessionServiceHeader.Size + NetBiosSessionRequest.PayloadLength, wireBytes.Length, "Unexpected NetBIOS SESSION_REQUEST wire length.");

                            NetBiosSessionRequest parsed = NetBiosSessionRequest.ReadFrom(wireBytes);
                            TestAssertions.SequenceEqual(called.RawName, parsed.CalledName.RawName, "Unexpected NetBIOS SESSION_REQUEST called name after round-trip.");
                            TestAssertions.SequenceEqual(calling.RawName, parsed.CallingName.RawName, "Unexpected NetBIOS SESSION_REQUEST calling name after round-trip.");

                            byte[] tampered = (byte[])wireBytes.Clone();
                            tampered[NetBiosSessionServiceHeader.Size] = 0x21;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosSessionRequest.ReadFrom(tampered),
                                "NetBIOS SESSION_REQUEST should reject an encoded-name length marker other than 0x20.");

                            byte[] truncated = new byte[NetBiosSessionServiceHeader.Size + NetBiosSessionRequest.PayloadLength - 1];
                            Buffer.BlockCopy(wireBytes, 0, truncated, 0, truncated.Length);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosSessionRequest.ReadFrom(truncated),
                                "NetBIOS SESSION_REQUEST should reject buffers that are too short.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "NetBiosNegativeSessionResponseRoundTripsErrorCodeAndRejectsMalformedShapes",
                        displayName: "Bounded NetBIOS NEGATIVE_SESSION_RESPONSE round-trips error code and rejects malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NetBiosNegativeSessionResponse response = new NetBiosNegativeSessionResponse
                            {
                                ErrorCode = NetBiosNegativeSessionResponseErrorCode.CalledNameNotPresent
                            };

                            byte[] wireBytes = response.ToByteArray();
                            TestAssertions.Equal(NetBiosSessionServiceHeader.Size + NetBiosNegativeSessionResponse.PayloadLength, wireBytes.Length, "Unexpected NetBIOS NEGATIVE_SESSION_RESPONSE wire length.");

                            NetBiosNegativeSessionResponse parsed = NetBiosNegativeSessionResponse.ReadFrom(wireBytes);
                            TestAssertions.Equal(NetBiosNegativeSessionResponseErrorCode.CalledNameNotPresent, parsed.ErrorCode, "Unexpected NetBIOS NEGATIVE_SESSION_RESPONSE error code after round-trip.");

                            byte[] tamperedHeader = (byte[])wireBytes.Clone();
                            tamperedHeader[0] = (byte)NetBiosSessionMessageType.SessionMessage;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosNegativeSessionResponse.ReadFrom(tamperedHeader),
                                "NetBIOS NEGATIVE_SESSION_RESPONSE should reject PDUs with a non-NEGATIVE_SESSION_RESPONSE message type.");

                            byte[] tamperedLength = (byte[])wireBytes.Clone();
                            tamperedLength[2] = 0x00;
                            tamperedLength[3] = 0x02;
                            byte[] grown = new byte[wireBytes.Length + 1];
                            Buffer.BlockCopy(tamperedLength, 0, grown, 0, tamperedLength.Length);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetBiosNegativeSessionResponse.ReadFrom(grown),
                                "NetBIOS NEGATIVE_SESSION_RESPONSE should reject PDUs whose declared length is not 1.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1Transaction2RequestRoundTripsSubCommandWithAlignedParameterAndDataBlocks",
                        displayName: "Bounded SMB1 TRANSACTION2 request round-trips sub-command with aligned parameter and data blocks",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x05, 0x01, 0x00, 0x00, 0x07, 0x01 };
                            byte[] data = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0 };

                            Smb1Transaction2Request request = new Smb1Transaction2Request
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction2,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                SubCommand = Smb1Transaction2SubCommand.QueryPathInformation,
                                TotalParameterCount = (ushort)parameters.Length,
                                TotalDataCount = (ushort)data.Length,
                                MaxParameterCount = 0x0040,
                                MaxDataCount = 0x4000,
                                MaxSetupCount = 0,
                                Flags = 0,
                                Timeout = 0,
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] requestBytes = request.ToByteArray();
                            Smb1Transaction2Request parsedRequest = Smb1Transaction2Request.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.SubCommand, parsedRequest.SubCommand, "Unexpected SMB1 TRANSACTION2 SubCommand after round-trip.");
                            TestAssertions.Equal(request.TotalParameterCount, parsedRequest.TotalParameterCount, "Unexpected SMB1 TRANSACTION2 TotalParameterCount after round-trip.");
                            TestAssertions.Equal(request.TotalDataCount, parsedRequest.TotalDataCount, "Unexpected SMB1 TRANSACTION2 TotalDataCount after round-trip.");
                            TestAssertions.SequenceEqual(parameters, parsedRequest.Parameters, "Unexpected SMB1 TRANSACTION2 Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedRequest.Data, "Unexpected SMB1 TRANSACTION2 Data after round-trip.");

                            byte[] tampered = (byte[])requestBytes.Clone();
                            int byteCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (15 * sizeof(ushort));
                            tampered[byteCountIndex] = 0xFF;
                            tampered[byteCountIndex + 1] = 0xFF;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1Transaction2Request.ReadFrom(tampered),
                                "SMB1 TRANSACTION2 request should reject ByteCount that exceeds the buffer.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1Transaction2ResponseRoundTripsParameterAndDataBlocksAndRejectsMalformedShapes",
                        displayName: "Bounded SMB1 TRANSACTION2 response round-trips parameter and data blocks and rejects malformed shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x00, 0x00 };
                            byte[] data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02 };

                            Smb1Transaction2Response response = new Smb1Transaction2Response
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction2,
                                    Status = NtStatus.Success,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = (ushort)parameters.Length,
                                TotalDataCount = (ushort)data.Length,
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] responseBytes = response.ToByteArray();
                            Smb1Transaction2Response parsedResponse = Smb1Transaction2Response.ReadFrom(responseBytes);
                            TestAssertions.SequenceEqual(parameters, parsedResponse.Parameters, "Unexpected SMB1 TRANSACTION2 response Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedResponse.Data, "Unexpected SMB1 TRANSACTION2 response Data after round-trip.");

                            byte[] tampered = (byte[])responseBytes.Clone();
                            int setupCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (10 * sizeof(ushort));
                            tampered[setupCountIndex] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1Transaction2Response.ReadFrom(tampered),
                                "SMB1 TRANSACTION2 response should reject non-zero SetupCount.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1TransactionRequestRoundTripsUnicodePipeNameAndSetupWordsAndRejectsMismatchedSetupCount",
                        displayName: "Bounded SMB1 TRANSACTION request round-trips Unicode pipe name and setup words and rejects mismatched SetupCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x01, 0x00, 0x02, 0x00 };
                            byte[] data = new byte[] { 0xAA, 0xBB, 0xCC };

                            Smb1TransactionRequest request = new Smb1TransactionRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Transaction,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                TotalParameterCount = (ushort)parameters.Length,
                                TotalDataCount = (ushort)data.Length,
                                MaxParameterCount = 0x40,
                                MaxDataCount = 0x4000,
                                MaxSetupCount = 0,
                                Flags = 0,
                                Timeout = 0,
                                Setup = new ushort[] { 0x0026, 0x4242 },
                                Name = "\\PIPE\\LANMAN",
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] requestBytes = request.ToByteArray();
                            Smb1TransactionRequest parsedRequest = Smb1TransactionRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.Name, parsedRequest.Name, "Unexpected SMB1 TRANSACTION Name after round-trip.");
                            TestAssertions.Equal(2, parsedRequest.Setup.Length, "Unexpected SMB1 TRANSACTION Setup count after round-trip.");
                            TestAssertions.Equal(request.Setup[0], parsedRequest.Setup[0], "Unexpected SMB1 TRANSACTION Setup[0] after round-trip.");
                            TestAssertions.Equal(request.Setup[1], parsedRequest.Setup[1], "Unexpected SMB1 TRANSACTION Setup[1] after round-trip.");
                            TestAssertions.SequenceEqual(parameters, parsedRequest.Parameters, "Unexpected SMB1 TRANSACTION Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedRequest.Data, "Unexpected SMB1 TRANSACTION Data after round-trip.");

                            byte[] tampered = (byte[])requestBytes.Clone();
                            int setupCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + (13 * sizeof(ushort));
                            tampered[setupCountIndex] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1TransactionRequest.ReadFrom(tampered),
                                "SMB1 TRANSACTION request should reject SetupCount that disagrees with the WordCount-implied setup-word count.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NtTransactRequestRoundTripsFunctionAnd32BitParameterDataLengthsAndRejectsMismatchedSetupCount",
                        displayName: "Bounded SMB1 NT_TRANSACT request round-trips Function and 32-bit parameter/data lengths and rejects mismatched SetupCount",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] parameters = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50, 0x60 };
                            byte[] data = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };

                            Smb1NtTransactRequest request = new Smb1NtTransactRequest
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.NtTransact,
                                    Flags = Smb1HeaderFlags.CaseInsensitive,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                                    Signature = new byte[8],
                                    TreeId = 0xCAFE,
                                    UserId = 0x1234,
                                    MultiplexId = 0x4242
                                },
                                MaxSetupCount = 0,
                                TotalParameterCount = (uint)parameters.Length,
                                TotalDataCount = (uint)data.Length,
                                MaxParameterCount = 0x0000_FFFFU,
                                MaxDataCount = 0x0010_0000U,
                                Function = 0x0004,
                                Setup = new ushort[] { 0x4242, 0x0001, 0x0040 },
                                Parameters = parameters,
                                Data = data
                            };

                            byte[] requestBytes = request.ToByteArray();
                            Smb1NtTransactRequest parsedRequest = Smb1NtTransactRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(request.Function, parsedRequest.Function, "Unexpected SMB1 NT_TRANSACT Function after round-trip.");
                            TestAssertions.Equal(request.MaxParameterCount, parsedRequest.MaxParameterCount, "Unexpected SMB1 NT_TRANSACT MaxParameterCount after round-trip.");
                            TestAssertions.Equal(request.MaxDataCount, parsedRequest.MaxDataCount, "Unexpected SMB1 NT_TRANSACT MaxDataCount after round-trip.");
                            TestAssertions.Equal(3, parsedRequest.Setup.Length, "Unexpected SMB1 NT_TRANSACT Setup count after round-trip.");
                            TestAssertions.SequenceEqual(parameters, parsedRequest.Parameters, "Unexpected SMB1 NT_TRANSACT Parameters after round-trip.");
                            TestAssertions.SequenceEqual(data, parsedRequest.Data, "Unexpected SMB1 NT_TRANSACT Data after round-trip.");

                            byte[] tampered = (byte[])requestBytes.Clone();
                            int setupCountIndex = ProtocolConstants.Smb1HeaderLength + 1 + 1 + 2 + (4 * sizeof(uint)) + (4 * sizeof(uint));
                            tampered[setupCountIndex] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NtTransactRequest.ReadFrom(tampered),
                                "SMB1 NT_TRANSACT request should reject SetupCount that disagrees with the WordCount-implied setup-word count.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb1Negotiate",
                        caseId: "Smb1NegotiateResponseRejectsMalformedAndNonExtendedSecurityShapes",
                        displayName: "Bounded SMB1 NEGOTIATE response rejects malformed shapes and non-extended-security responses",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb1NegotiateResponse.ReadFrom(new byte[10]),
                                "A truncated SMB1 negotiate response should fail to parse.");

                            Smb1NegotiateResponse missingExtendedSecurity = new Smb1NegotiateResponse
                            {
                                Header = new Smb1Header
                                {
                                    Command = Smb1Command.Negotiate,
                                    Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                                    Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus
                                },
                                DialectIndex = 0,
                                SecurityMode = Smb1SecurityMode.UserSecurity | Smb1SecurityMode.EncryptPasswords,
                                Capabilities = Smb1Capabilities.Unicode | Smb1Capabilities.NtSmbs
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => missingExtendedSecurity.ToByteArray(),
                                "The bounded SMB1 negotiate response codec should reject responses without the extended-security capability.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 session and tree-message suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2SessionTreeSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2SessionTree",
                displayName: "SMB2 session and tree messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2SessionTree",
                        caseId: "Smb2SessionAndTreeMessagesRoundTrip",
                        displayName: "SMB2 session, tree, and internal auth tokens round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            OpenCifsNtlmNegotiateToken negotiateToken = new OpenCifsNtlmNegotiateToken
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP"
                            };
                            byte[] negotiateTokenBytes = negotiateToken.ToByteArray();
                            OpenCifsNtlmNegotiateToken parsedNegotiateToken = OpenCifsNtlmNegotiateToken.ReadFrom(negotiateTokenBytes);
                            TestAssertions.Equal("alice", parsedNegotiateToken.UserName, "The internal NTLM negotiate token user name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedNegotiateToken.UserDomain, "The internal NTLM negotiate token domain changed.");

                            Smb2SessionSetupRequest sessionSetupRequest = new Smb2SessionSetupRequest
                            {
                                Flags = 0,
                                SecurityMode = Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired,
                                Capabilities = Smb2GlobalCapabilities.None,
                                Channel = 0,
                                PreviousSessionId = 0,
                                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenInit(new SpnegoNegTokenInit
                                {
                                    MechanismTypes = new string[] { SpnegoMechanismOid.Ntlm },
                                    MechanismToken = negotiateTokenBytes
                                })
                            };

                            Smb2SessionSetupRequestValidator.Validate(sessionSetupRequest);
                            byte[] encodedSessionSetupRequest = sessionSetupRequest.ToByteArray();
                            Smb2SessionSetupRequest parsedSessionSetupRequest = Smb2SessionSetupRequest.ReadFrom(encodedSessionSetupRequest);
                            Smb2SessionSetupRequestValidator.Validate(parsedSessionSetupRequest);
                            TestAssertions.Equal(sessionSetupRequest.SecurityMode, parsedSessionSetupRequest.SecurityMode, "The SMB2 session-setup request security mode changed.");

                            Smb2SessionSetupRequest signingRequiredOnlyRequest = new Smb2SessionSetupRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningRequired,
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            Smb2SessionSetupRequestValidator.Validate(signingRequiredOnlyRequest);

                            SpnegoNegTokenInit parsedInitToken = SpnegoTokenCodec.DecodeNegTokenInit(parsedSessionSetupRequest.SecurityBuffer);
                            OpenCifsNtlmNegotiateToken parsedInitMechanismToken = OpenCifsNtlmNegotiateToken.ReadFrom(parsedInitToken.MechanismToken!);
                            TestAssertions.Equal("alice", parsedInitMechanismToken.UserName, "The session-setup request mechanism token user name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedInitMechanismToken.UserDomain, "The session-setup request mechanism token domain changed.");

                            OpenCifsNtlmChallengeToken challengeToken = new OpenCifsNtlmChallengeToken
                            {
                                ServerChallenge = Hex("0123456789ABCDEF"),
                                ServerName = "LAB-SERVER",
                                TargetDomain = "WORKGROUP"
                            };
                            byte[] challengeTokenBytes = challengeToken.ToByteArray();
                            OpenCifsNtlmChallengeToken parsedChallengeToken = OpenCifsNtlmChallengeToken.ReadFrom(challengeTokenBytes);
                            TestAssertions.SequenceEqual(Hex("0123456789ABCDEF"), parsedChallengeToken.ServerChallenge, "The internal NTLM challenge token challenge bytes changed.");
                            TestAssertions.Equal("LAB-SERVER", parsedChallengeToken.ServerName, "The internal NTLM challenge token server name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedChallengeToken.TargetDomain, "The internal NTLM challenge token target domain changed.");

                            Smb2SessionSetupResponse sessionSetupResponse = new Smb2SessionSetupResponse
                            {
                                SessionFlags = Smb2SessionFlags.None,
                                SecurityBuffer = SpnegoTokenCodec.EncodeNegTokenResp(new SpnegoNegTokenResp
                                {
                                    NegotiationState = SpnegoNegState.AcceptIncomplete,
                                    SupportedMechanism = SpnegoMechanismOid.Ntlm,
                                    ResponseToken = challengeTokenBytes
                                })
                            };

                            Smb2SessionSetupResponseValidator.Validate(sessionSetupResponse);
                            byte[] encodedSessionSetupResponse = sessionSetupResponse.ToByteArray();
                            Smb2SessionSetupResponse parsedSessionSetupResponse = Smb2SessionSetupResponse.ReadFrom(encodedSessionSetupResponse);
                            Smb2SessionSetupResponseValidator.Validate(parsedSessionSetupResponse);
                            SpnegoNegTokenResp parsedChallengeResponse = SpnegoTokenCodec.DecodeNegTokenResp(parsedSessionSetupResponse.SecurityBuffer);
                            OpenCifsNtlmChallengeToken parsedChallengeMechanismToken = OpenCifsNtlmChallengeToken.ReadFrom(parsedChallengeResponse.ResponseToken!);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, parsedChallengeResponse.NegotiationState!.Value, "The session-setup response negotiation state changed.");
                            TestAssertions.Equal("LAB-SERVER", parsedChallengeMechanismToken.ServerName, "The session-setup response mechanism token server name changed.");

                            OpenCifsNtlmAuthenticateToken authenticateToken = new OpenCifsNtlmAuthenticateToken
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP",
                                NtChallengeResponse = Hex("00112233445566778899AABBCCDDEEFF0102030405060708090A0B0C0D0E0F10"),
                                LmChallengeResponse = Hex("FFEEDDCCBBAA998877665544332211000102030405060708")
                            };
                            byte[] authenticateTokenBytes = authenticateToken.ToByteArray();
                            OpenCifsNtlmAuthenticateToken parsedAuthenticateToken = OpenCifsNtlmAuthenticateToken.ReadFrom(authenticateTokenBytes);
                            TestAssertions.Equal("alice", parsedAuthenticateToken.UserName, "The internal NTLM authenticate token user name changed.");
                            TestAssertions.Equal("WORKGROUP", parsedAuthenticateToken.UserDomain, "The internal NTLM authenticate token domain changed.");
                            TestAssertions.SequenceEqual(authenticateToken.NtChallengeResponse, parsedAuthenticateToken.NtChallengeResponse, "The internal NTLM authenticate token NT response changed.");
                            TestAssertions.SequenceEqual(authenticateToken.LmChallengeResponse, parsedAuthenticateToken.LmChallengeResponse, "The internal NTLM authenticate token LM response changed.");

                            Smb2TreeConnectRequest treeConnectRequest = new Smb2TreeConnectRequest
                            {
                                Flags = 0,
                                Path = "\\\\LAB-SERVER\\share"
                            };

                            Smb2TreeConnectRequestValidator.Validate(treeConnectRequest);
                            byte[] encodedTreeConnectRequest = treeConnectRequest.ToByteArray();
                            Smb2TreeConnectRequest parsedTreeConnectRequest = Smb2TreeConnectRequest.ReadFrom(encodedTreeConnectRequest);
                            Smb2TreeConnectRequestValidator.Validate(parsedTreeConnectRequest);
                            TestAssertions.Equal("\\\\LAB-SERVER\\share", parsedTreeConnectRequest.Path, "The SMB2 tree-connect path changed.");

                            Smb2TreeConnectResponse treeConnectResponse = new Smb2TreeConnectResponse
                            {
                                ShareType = Smb2ShareType.Disk,
                                ShareFlags = 0x00000003,
                                Capabilities = 0x00000008,
                                MaximalAccess = 0x001F01FF
                            };

                            Smb2TreeConnectResponseValidator.Validate(treeConnectResponse);
                            byte[] encodedTreeConnectResponse = treeConnectResponse.ToByteArray();
                            Smb2TreeConnectResponse parsedTreeConnectResponse = Smb2TreeConnectResponse.ReadFrom(encodedTreeConnectResponse);
                            Smb2TreeConnectResponseValidator.Validate(parsedTreeConnectResponse);
                            TestAssertions.Equal(Smb2ShareType.Disk, parsedTreeConnectResponse.ShareType, "The SMB2 tree-connect response share type changed.");
                            TestAssertions.Equal(0x001F01FFU, parsedTreeConnectResponse.MaximalAccess, "The SMB2 tree-connect response maximal access changed.");

                            Smb2TreeDisconnectRequest treeDisconnectRequest = new Smb2TreeDisconnectRequest();
                            byte[] encodedTreeDisconnectRequest = treeDisconnectRequest.ToByteArray();
                            Smb2TreeDisconnectRequest parsedTreeDisconnectRequest = Smb2TreeDisconnectRequest.ReadFrom(encodedTreeDisconnectRequest);
                            Smb2TreeDisconnectRequestValidator.Validate(parsedTreeDisconnectRequest);

                            Smb2TreeDisconnectResponse treeDisconnectResponse = new Smb2TreeDisconnectResponse();
                            byte[] encodedTreeDisconnectResponse = treeDisconnectResponse.ToByteArray();
                            Smb2TreeDisconnectResponse parsedTreeDisconnectResponse = Smb2TreeDisconnectResponse.ReadFrom(encodedTreeDisconnectResponse);
                            Smb2TreeDisconnectResponseValidator.Validate(parsedTreeDisconnectResponse);

                            Smb2LogoffRequest logoffRequest = new Smb2LogoffRequest();
                            byte[] encodedLogoffRequest = logoffRequest.ToByteArray();
                            Smb2LogoffRequest parsedLogoffRequest = Smb2LogoffRequest.ReadFrom(encodedLogoffRequest);
                            Smb2LogoffRequestValidator.Validate(parsedLogoffRequest);

                            Smb2LogoffResponse logoffResponse = new Smb2LogoffResponse();
                            byte[] encodedLogoffResponse = logoffResponse.ToByteArray();
                            Smb2LogoffResponse parsedLogoffResponse = Smb2LogoffResponse.ReadFrom(encodedLogoffResponse);
                            Smb2LogoffResponseValidator.Validate(parsedLogoffResponse);
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2SessionTree",
                        caseId: "Smb2SessionAndTreeMessagesRejectMalformedInputs",
                        displayName: "SMB2 session, tree, and internal auth token codecs reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2SessionSetupRequest invalidSessionSetupRequest = new Smb2SessionSetupRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            byte[] invalidSessionSetupRequestBytes = invalidSessionSetupRequest.ToByteArray();
                            invalidSessionSetupRequestBytes[12] = 0x44;
                            invalidSessionSetupRequestBytes[13] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2SessionSetupRequest.ReadFrom(invalidSessionSetupRequestBytes),
                                "An SMB2 session-setup request with an invalid security-buffer offset should fail to parse.");

                            Smb2SessionSetupRequest emptySecurityBufferRequest = new Smb2SessionSetupRequest
                            {
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                SecurityBuffer = Array.Empty<byte>()
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2SessionSetupRequestValidator.Validate(emptySecurityBufferRequest),
                                "An SMB2 session-setup request without a security buffer should fail validation.");

                            Smb2SessionSetupResponse invalidSessionSetupResponse = new Smb2SessionSetupResponse
                            {
                                SecurityBuffer = new byte[] { 0xAA }
                            };
                            byte[] invalidSessionSetupResponseBytes = invalidSessionSetupResponse.ToByteArray();
                            invalidSessionSetupResponseBytes[4] = 0x44;
                            invalidSessionSetupResponseBytes[5] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2SessionSetupResponse.ReadFrom(invalidSessionSetupResponseBytes),
                                "An SMB2 session-setup response with an invalid security-buffer offset should fail to parse.");

                            Smb2TreeConnectRequest invalidTreeConnectRequest = new Smb2TreeConnectRequest
                            {
                                Path = "\\\\LAB-SERVER\\share"
                            };
                            byte[] invalidTreeConnectRequestBytes = invalidTreeConnectRequest.ToByteArray();
                            invalidTreeConnectRequestBytes[6] = 0x03;
                            invalidTreeConnectRequestBytes[7] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2TreeConnectRequest.ReadFrom(invalidTreeConnectRequestBytes),
                                "An SMB2 tree-connect request with an odd path length should fail to parse.");

                            Smb2TreeConnectResponse invalidTreeConnectResponse = new Smb2TreeConnectResponse
                            {
                                ShareType = (Smb2ShareType)0x7F
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2TreeConnectResponseValidator.Validate(invalidTreeConnectResponse),
                                "An SMB2 tree-connect response with an unknown share type should fail validation.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2TreeDisconnectRequest.ReadFrom(new byte[3]),
                                "A truncated SMB2 tree-disconnect request should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2TreeDisconnectResponse.ReadFrom(new byte[3]),
                                "A truncated SMB2 tree-disconnect response should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LogoffRequest.ReadFrom(new byte[3]),
                                "A truncated SMB2 logoff request should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LogoffResponse.ReadFrom(new byte[3]),
                                "A truncated SMB2 logoff response should fail to parse.");

                            byte[] authenticateTokenBytes = new OpenCifsNtlmAuthenticateToken
                            {
                                UserName = "alice",
                                UserDomain = "WORKGROUP",
                                NtChallengeResponse = Hex("00112233445566778899AABBCCDDEEFF"),
                                LmChallengeResponse = Hex("FFEEDDCCBBAA99887766554433221100")
                            }.ToByteArray();
                            byte[] malformedAuthenticateTokenBytes = Combine(authenticateTokenBytes, new byte[] { 0x00 });
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => OpenCifsNtlmAuthenticateToken.ReadFrom(malformedAuthenticateTokenBytes),
                                "An internal NTLM authenticate token with trailing bytes should fail to parse.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 echo suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2EchoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Echo",
                displayName: "SMB2 echo codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Echo",
                        caseId: "EchoMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 echo messages round-trip and trim compounded zero padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2EchoRequest echoRequest = new Smb2EchoRequest();
                            byte[] encodedEchoRequest = echoRequest.ToByteArray();
                            Smb2EchoRequest parsedEchoRequest = Smb2EchoRequest.ReadFrom(encodedEchoRequest);
                            Smb2EchoRequestValidator.Validate(parsedEchoRequest);
                            TestAssertions.SequenceEqual(encodedEchoRequest, parsedEchoRequest.ToByteArray(), "The SMB2 echo request encoding changed.");

                            byte[] paddedEchoRequest = Combine(encodedEchoRequest, new byte[4]);
                            byte[] trimmedEchoRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Echo, paddedEchoRequest);
                            TestAssertions.SequenceEqual(encodedEchoRequest, trimmedEchoRequest, "Unexpected compounded SMB2 echo request trimming result.");

                            Smb2EchoResponse echoResponse = new Smb2EchoResponse();
                            byte[] encodedEchoResponse = echoResponse.ToByteArray();
                            Smb2EchoResponse parsedEchoResponse = Smb2EchoResponse.ReadFrom(encodedEchoResponse);
                            Smb2EchoResponseValidator.Validate(parsedEchoResponse);
                            TestAssertions.SequenceEqual(encodedEchoResponse, parsedEchoResponse.ToByteArray(), "The SMB2 echo response encoding changed.");

                            byte[] paddedEchoResponse = Combine(encodedEchoResponse, new byte[4]);
                            byte[] trimmedEchoResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Echo, paddedEchoResponse);
                            TestAssertions.SequenceEqual(encodedEchoResponse, trimmedEchoResponse, "Unexpected compounded SMB2 echo response trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Echo",
                        caseId: "EchoMessagesRejectMalformedInputs",
                        displayName: "SMB2 echo codecs reject truncated or null inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2EchoRequest.ReadFrom(new byte[3]),
                                "A truncated SMB2 echo request should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2EchoResponse.ReadFrom(new byte[3]),
                                "A truncated SMB2 echo response should fail to parse.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2EchoRequestValidator.Validate(null!),
                                "A null SMB2 echo request should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2EchoResponseValidator.Validate(null!),
                                "A null SMB2 echo response should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 cancel suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2CancelSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Cancel",
                displayName: "SMB2 cancel codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Cancel",
                        caseId: "CancelMessagesRoundTripAndTrimCompoundedPayload",
                        displayName: "SMB2 cancel requests round-trip through wire encoding and compounded request trimming",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CancelRequest cancelRequest = new Smb2CancelRequest();
                            byte[] encodedCancelRequest = cancelRequest.ToByteArray();
                            Smb2CancelRequest parsedCancelRequest = Smb2CancelRequest.ReadFrom(encodedCancelRequest);
                            Smb2CancelRequestValidator.Validate(parsedCancelRequest);
                            TestAssertions.SequenceEqual(encodedCancelRequest, parsedCancelRequest.ToByteArray(), "The SMB2 cancel request encoding changed.");

                            byte[] paddedCancelRequest = Combine(encodedCancelRequest, new byte[4]);
                            byte[] trimmedCancelRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Cancel, paddedCancelRequest);
                            TestAssertions.SequenceEqual(encodedCancelRequest, trimmedCancelRequest, "Unexpected compounded SMB2 cancel request trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Cancel",
                        caseId: "CancelMessagesRejectMalformedInputs",
                        displayName: "SMB2 cancel requests reject malformed inputs and null validation targets",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CancelRequest.ReadFrom(new byte[3]),
                                "The SMB2 cancel request requires a 4-byte fixed body.");

                            byte[] malformedCancelRequestBytes = new Smb2CancelRequest().ToByteArray();
                            malformedCancelRequestBytes[0] = 0x05;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CancelRequest.ReadFrom(malformedCancelRequestBytes),
                                "Malformed SMB2 cancel requests should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CancelRequestValidator.Validate(null!),
                                "A null SMB2 cancel request should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 CHANGE_NOTIFY suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2ChangeNotifySuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2ChangeNotify",
                displayName: "SMB2 CHANGE_NOTIFY codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2ChangeNotify",
                        caseId: "ChangeNotifyMessagesAndAsyncHeadersRoundTrip",
                        displayName: "SMB2 async headers and CHANGE_NOTIFY messages round-trip and trim compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header asyncHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Pending,
                                Command = Smb2Command.ChangeNotify,
                                CreditRequest = 3,
                                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                NextCommand = 0,
                                MessageId = 9,
                                AsyncId = 77,
                                SessionId = 88,
                                Signature = new byte[16]
                            };
                            byte[] encodedAsyncHeader = asyncHeader.ToByteArray();
                            Smb2Header parsedAsyncHeader = Smb2Header.ReadFrom(encodedAsyncHeader);
                            Smb2HeaderValidator.Validate(parsedAsyncHeader);
                            TestAssertions.Equal(77UL, parsedAsyncHeader.AsyncId, "Unexpected SMB2 async identifier.");
                            TestAssertions.Equal(0U, parsedAsyncHeader.ProcessId, "Unexpected SMB2 async ProcessId value.");
                            TestAssertions.Equal(0U, parsedAsyncHeader.TreeId, "Unexpected SMB2 async TreeId value.");

                            Smb2CompoundPacket asyncResponsePacket = new Smb2CompoundPacket(new[]
                            {
                                new Smb2CompoundPacketEntry(asyncHeader, new Smb2ErrorResponse().ToByteArray())
                            });
                            Smb2CompoundPacket parsedAsyncResponsePacket = Smb2CompoundPacket.ReadFrom(asyncResponsePacket.ToByteArray());
                            TestAssertions.Equal(77UL, parsedAsyncResponsePacket.Entries[0].Header.AsyncId, "Expected the compounded async response to preserve AsyncId.");

                            Smb2ChangeNotifyRequest request = new Smb2ChangeNotifyRequest
                            {
                                Flags = Smb2ChangeNotifyFlags.WatchTree,
                                OutputBufferLength = 4096,
                                PersistentFileId = 10,
                                VolatileFileId = 11,
                                CompletionFilter = FileNotifyChangeFilter.FileName | FileNotifyChangeFilter.LastWrite
                            };
                            byte[] encodedRequest = request.ToByteArray();
                            Smb2ChangeNotifyRequest parsedRequest = Smb2ChangeNotifyRequest.ReadFrom(encodedRequest);
                            Smb2ChangeNotifyRequestValidator.Validate(parsedRequest);
                            byte[] trimmedRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.ChangeNotify, Combine(encodedRequest, new byte[4]));
                            TestAssertions.SequenceEqual(encodedRequest, trimmedRequest, "Unexpected compounded SMB2 CHANGE_NOTIFY request trimming result.");

                            FileNotifyInformation[] expectedEntries = new FileNotifyInformation[]
                            {
                                new FileNotifyInformation
                                {
                                    Action = FileNotifyAction.Added,
                                    FileName = "child.txt"
                                },
                                new FileNotifyInformation
                                {
                                    Action = FileNotifyAction.Modified,
                                    FileName = "subdir\\leaf.txt"
                                }
                            };
                            byte[] encodedEntries = FileNotifyInformation.EncodeEntries(expectedEntries);
                            FileNotifyInformation[] decodedEntries = FileNotifyInformation.DecodeEntries(encodedEntries);
                            TestAssertions.Equal(2, decodedEntries.Length, "Expected the FILE_NOTIFY_INFORMATION buffer to preserve both entries.");
                            TestAssertions.Equal(FileNotifyAction.Added, decodedEntries[0].Action, "Unexpected first notify action.");
                            TestAssertions.Equal("subdir\\leaf.txt", decodedEntries[1].FileName, "Unexpected second notify path.");

                            Smb2ChangeNotifyResponse response = new Smb2ChangeNotifyResponse
                            {
                                OutputBuffer = encodedEntries
                            };
                            byte[] encodedResponse = response.ToByteArray();
                            Smb2ChangeNotifyResponse parsedResponse = Smb2ChangeNotifyResponse.ReadFrom(encodedResponse);
                            Smb2ChangeNotifyResponseValidator.Validate(parsedResponse);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.ChangeNotify, Combine(encodedResponse, new byte[4]));
                            TestAssertions.SequenceEqual(encodedResponse, trimmedResponse, "Unexpected compounded SMB2 CHANGE_NOTIFY response trimming result.");

                            Smb2ErrorResponse errorResponse = new Smb2ErrorResponse();
                            byte[] encodedErrorResponse = errorResponse.ToByteArray();
                            Smb2ErrorResponse parsedErrorResponse = Smb2ErrorResponse.ReadFrom(encodedErrorResponse);
                            Smb2ErrorResponseValidator.Validate(parsedErrorResponse);
                            TestAssertions.Equal(0, parsedErrorResponse.ErrorData.Length, "Expected the bounded SMB2 error response to remain empty.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2ChangeNotify",
                        caseId: "ChangeNotifyMessagesRejectMalformedInputs",
                        displayName: "SMB2 async headers and CHANGE_NOTIFY codecs reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2Header invalidAsyncHeader = new Smb2Header
                            {
                                CreditCharge = 0,
                                Status = NtStatus.Pending,
                                Command = Smb2Command.ChangeNotify,
                                CreditRequest = 1,
                                Flags = Smb2HeaderFlags.ServerToRedir | Smb2HeaderFlags.AsyncCommand,
                                MessageId = 5,
                                SessionId = 6,
                                Signature = new byte[16]
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2HeaderValidator.Validate(invalidAsyncHeader),
                                "Async SMB2 headers without an AsyncId should fail validation.");

                            byte[] malformedRequest = new Smb2ChangeNotifyRequest().ToByteArray();
                            malformedRequest[0] = 0x1F;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2ChangeNotifyRequest.ReadFrom(malformedRequest),
                                "Malformed SMB2 CHANGE_NOTIFY requests should be rejected.");

                            byte[] malformedResponse = new Smb2ChangeNotifyResponse
                            {
                                OutputBuffer = new byte[] { 0x01, 0x02 }
                            }.ToByteArray();
                            malformedResponse[2] = 0x01;
                            malformedResponse[3] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2ChangeNotifyResponse.ReadFrom(malformedResponse),
                                "Malformed SMB2 CHANGE_NOTIFY responses should be rejected.");

                            byte[] malformedNotifyEntries = FileNotifyInformation.EncodeEntries(new FileNotifyInformation[]
                            {
                                new FileNotifyInformation
                                {
                                    Action = FileNotifyAction.Added,
                                    FileName = "child.txt"
                                }
                            });
                            malformedNotifyEntries[8] = 0x01;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileNotifyInformation.DecodeEntries(malformedNotifyEntries),
                                "Malformed FILE_NOTIFY_INFORMATION buffers should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ChangeNotifyRequestValidator.Validate(null!),
                                "A null SMB2 CHANGE_NOTIFY request should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ChangeNotifyResponseValidator.Validate(null!),
                                "A null SMB2 CHANGE_NOTIFY response should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ErrorResponseValidator.Validate(null!),
                                "A null SMB2 error response should fail validation.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 file-I/O suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2FileIoSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2FileIo",
                displayName: "SMB2 create, read, write, flush, and close messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2FileIo",
                        caseId: "CreateAndCloseMessagesRoundTrip",
                        displayName: "SMB2 create, flush, and close messages round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest createRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0000000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "folder\\notes.txt",
                                CreateContexts = Array.Empty<byte>()
                            };

                            byte[] encodedCreateRequest = createRequest.ToByteArray();
                            Smb2CreateRequest parsedCreateRequest = Smb2CreateRequest.ReadFrom(encodedCreateRequest);
                            Smb2CreateRequestValidator.Validate(parsedCreateRequest);
                            TestAssertions.Equal("folder\\notes.txt", parsedCreateRequest.Name, "Unexpected create-request path.");
                            TestAssertions.Equal(0xC0000000U, parsedCreateRequest.DesiredAccess, "Unexpected create-request access mask.");
                            TestAssertions.Equal(Smb2CreateDisposition.OpenIf, parsedCreateRequest.CreateDisposition, "Unexpected create-request disposition.");

                            Smb2CreateResponse createResponse = new Smb2CreateResponse
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                Flags = 0,
                                CreateAction = Smb2CreateAction.Created,
                                CreationTime = 0x0102030405060708UL,
                                LastAccessTime = 0x1112131415161718UL,
                                LastWriteTime = 0x2122232425262728UL,
                                ChangeTime = 0x3132333435363738UL,
                                AllocationSize = 4096,
                                EndOfFile = 17,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                PersistentFileId = 9,
                                VolatileFileId = 10,
                                CreateContexts = Array.Empty<byte>()
                            };

                            byte[] encodedCreateResponse = createResponse.ToByteArray();
                            Smb2CreateResponse parsedCreateResponse = Smb2CreateResponse.ReadFrom(encodedCreateResponse);
                            Smb2CreateResponseValidator.Validate(parsedCreateResponse);
                            TestAssertions.Equal(9UL, parsedCreateResponse.PersistentFileId, "Unexpected persistent file identifier.");
                            TestAssertions.Equal(10UL, parsedCreateResponse.VolatileFileId, "Unexpected volatile file identifier.");
                            TestAssertions.Equal(17UL, parsedCreateResponse.EndOfFile, "Unexpected create-response EOF size.");

                            Smb2FlushRequest flushRequest = new Smb2FlushRequest
                            {
                                PersistentFileId = 9,
                                VolatileFileId = 10
                            };
                            Smb2FlushRequest parsedFlushRequest = Smb2FlushRequest.ReadFrom(flushRequest.ToByteArray());
                            Smb2FlushRequestValidator.Validate(parsedFlushRequest);
                            TestAssertions.Equal(10UL, parsedFlushRequest.VolatileFileId, "Unexpected flush-request volatile file identifier.");

                            Smb2FlushResponse flushResponse = Smb2FlushResponse.ReadFrom(new Smb2FlushResponse().ToByteArray());
                            Smb2FlushResponseValidator.Validate(flushResponse);

                            Smb2CloseRequest closeRequest = new Smb2CloseRequest
                            {
                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                PersistentFileId = 9,
                                VolatileFileId = 10
                            };
                            Smb2CloseRequest parsedCloseRequest = Smb2CloseRequest.ReadFrom(closeRequest.ToByteArray());
                            Smb2CloseRequestValidator.Validate(parsedCloseRequest);
                            TestAssertions.Equal(Smb2CloseFlags.PostQueryAttributes, parsedCloseRequest.Flags, "Unexpected close-request flags.");

                            Smb2CloseResponse closeResponse = new Smb2CloseResponse
                            {
                                Flags = Smb2CloseFlags.PostQueryAttributes,
                                CreationTime = 0x0102030405060708UL,
                                LastAccessTime = 0x1112131415161718UL,
                                LastWriteTime = 0x2122232425262728UL,
                                ChangeTime = 0x3132333435363738UL,
                                AllocationSize = 4096,
                                EndOfFile = 17,
                                FileAttributes = ProtocolFileAttributes.Archive
                            };
                            Smb2CloseResponse parsedCloseResponse = Smb2CloseResponse.ReadFrom(closeResponse.ToByteArray());
                            Smb2CloseResponseValidator.Validate(parsedCloseResponse);
                            TestAssertions.Equal(ProtocolFileAttributes.Archive, parsedCloseResponse.FileAttributes, "Unexpected close-response file attributes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2FileIo",
                        caseId: "ReadAndWriteMessagesRoundTrip",
                        displayName: "SMB2 read and write messages round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2WriteRequest writeRequest = new Smb2WriteRequest
                            {
                                Offset = 128,
                                PersistentFileId = 17,
                                VolatileFileId = 18,
                                Channel = 0,
                                RemainingBytes = 0,
                                Flags = Smb2WriteFlags.None,
                                DataBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 },
                                WriteChannelInfo = Array.Empty<byte>()
                            };

                            Smb2WriteRequest parsedWriteRequest = Smb2WriteRequest.ReadFrom(writeRequest.ToByteArray());
                            Smb2WriteRequestValidator.Validate(parsedWriteRequest);
                            TestAssertions.Equal(128UL, parsedWriteRequest.Offset, "Unexpected write-request offset.");
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x20, 0x30, 0x40 }, parsedWriteRequest.DataBuffer, "Unexpected write-request data.");

                            Smb2WriteResponse writeResponse = new Smb2WriteResponse
                            {
                                Count = 4
                            };
                            Smb2WriteResponse parsedWriteResponse = Smb2WriteResponse.ReadFrom(writeResponse.ToByteArray());
                            Smb2WriteResponseValidator.Validate(parsedWriteResponse);
                            TestAssertions.Equal(4U, parsedWriteResponse.Count, "Unexpected write-response count.");

                            Smb2ReadRequest readRequest = new Smb2ReadRequest
                            {
                                Length = 4,
                                Offset = 128,
                                PersistentFileId = 17,
                                VolatileFileId = 18,
                                MinimumCount = 2,
                                Channel = 0,
                                RemainingBytes = 0,
                                ReadChannelInfo = Array.Empty<byte>()
                            };

                            Smb2ReadRequest parsedReadRequest = Smb2ReadRequest.ReadFrom(readRequest.ToByteArray());
                            Smb2ReadRequestValidator.Validate(parsedReadRequest);
                            TestAssertions.Equal(4U, parsedReadRequest.Length, "Unexpected read-request length.");
                            TestAssertions.Equal(2U, parsedReadRequest.MinimumCount, "Unexpected read-request minimum count.");

                            Smb2ReadResponse readResponse = new Smb2ReadResponse
                            {
                                DataBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 },
                                DataRemaining = 0,
                                Flags = 0
                            };

                            Smb2ReadResponse parsedReadResponse = Smb2ReadResponse.ReadFrom(readResponse.ToByteArray());
                            Smb2ReadResponseValidator.Validate(parsedReadResponse);
                            TestAssertions.SequenceEqual(new byte[] { 0x10, 0x20, 0x30, 0x40 }, parsedReadResponse.DataBuffer, "Unexpected read-response data.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2FileIo",
                        caseId: "FileIoValidatorsRejectUnsupportedCurrentSliceFeatures",
                        displayName: "SMB2 file-I/O validators allow bounded delete-on-close semantics and reject unsupported combinations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest deleteOnCloseRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                Name = "temp\\transient.txt",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(deleteOnCloseRequest);

                            Smb2CreateRequest directoryOpenRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80000000U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.DirectoryFile,
                                Name = "directory",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(directoryOpenRequest);

                            Smb2CreateRequest directoryCreateRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80000000U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Create,
                                CreateOptions = Smb2CreateOptions.DirectoryFile,
                                Name = "directory-created",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(directoryCreateRequest);

                            Smb2CreateRequest directoryDeleteOnCloseRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80010000U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateOptions = Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                Name = "directory-transient",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(directoryDeleteOnCloseRequest);

                            Smb2CreateRequest shareRootOpenRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0x80000080U,
                                FileAttributes = ProtocolFileAttributes.Directory,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.OpenReparsePoint,
                                Name = string.Empty,
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(shareRootOpenRequest);

                            Smb2CreateRequest createContextRequest = new Smb2CreateRequest
                            {
                                Name = "notes.txt",
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    new Smb2CreateContext
                                    {
                                        Name = Encoding.ASCII.GetBytes("ExtA"),
                                        Data = new byte[] { 0x01, 0x02, 0x03, 0x04 }
                                    }
                                })
                            };
                            Smb2CreateRequestValidator.Validate(createContextRequest);

                            LittleEndianWriter unpaddedCreateContextWriter = new LittleEndianWriter();
                            unpaddedCreateContextWriter.WriteUInt32(0);
                            unpaddedCreateContextWriter.WriteUInt16(16);
                            unpaddedCreateContextWriter.WriteUInt16(4);
                            unpaddedCreateContextWriter.WriteUInt16(0);
                            unpaddedCreateContextWriter.WriteUInt16(24);
                            unpaddedCreateContextWriter.WriteUInt32(12);
                            unpaddedCreateContextWriter.WriteBytes(Encoding.ASCII.GetBytes("ExtA"));
                            while (unpaddedCreateContextWriter.Length < 24)
                            {
                                unpaddedCreateContextWriter.WriteByte(0);
                            }

                            unpaddedCreateContextWriter.WriteBytes(new byte[]
                            {
                                0x01, 0x02, 0x03, 0x04,
                                0x05, 0x06, 0x07, 0x08,
                                0x09, 0x0A, 0x0B, 0x0C
                            });
                            Smb2CreateRequest unpaddedCreateContextRequest = new Smb2CreateRequest
                            {
                                Name = "notes.txt",
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                CreateDisposition = Smb2CreateDisposition.OpenIf,
                                CreateContexts = unpaddedCreateContextWriter.ToArray()
                            };
                            Smb2CreateRequestValidator.Validate(unpaddedCreateContextRequest);

                            Smb2CreateRequest toleratedSmb3HintContextRequest = new Smb2CreateRequest
                            {
                                Name = "directory",
                                DesiredAccess = 0x00100081U,
                                ShareAccess = 0x00000003U,
                                CreateDisposition = Smb2CreateDisposition.Create,
                                CreateOptions = Smb2CreateOptions.DirectoryFile | Smb2CreateOptions.OpenReparsePoint,
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    new Smb2DurableHandleRequestV2Context
                                    {
                                        Timeout = 0,
                                        Flags = Smb2DurableHandleFlags.None,
                                        CreateGuid = Guid.NewGuid()
                                    }.ToCreateContext(),
                                    new Smb2CreateRequestLeaseContext
                                    {
                                        LeaseKey = new byte[16],
                                        LeaseState = Smb2LeaseState.ReadCaching
                                    }.ToCreateContext()
                                })
                            };
                            Smb2CreateRequestValidator.Validate(toleratedSmb3HintContextRequest);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = string.Empty,
                                    DesiredAccess = 0x80000080U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Open,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Empty create names should reject non-directory share-root requests.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "directory",
                                    DesiredAccess = 0x80000000U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Overwrite,
                                    CreateOptions = Smb2CreateOptions.DirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Directory opens should reject unsupported create dispositions for the current SMB 2.0.2 directory slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "temp.txt",
                                    DesiredAccess = 0xC0000000U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.OpenIf,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile | Smb2CreateOptions.DeleteOnClose,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Delete-on-close should require DELETE access.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "temp.txt",
                                    DesiredAccess = 0xC0010000U,
                                    ShareAccess = 0x00000008U,
                                    CreateDisposition = Smb2CreateDisposition.OpenIf,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "Unsupported share-access bits should be rejected.");

                            Smb2CreateRequest supersedeRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.None,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Supersede,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "replace.txt",
                                CreateContexts = Array.Empty<byte>()
                            };
                            Smb2CreateRequestValidator.Validate(supersedeRequest);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "replace.txt",
                                    DesiredAccess = 0xC0000000U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Supersede,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Array.Empty<byte>()
                                }),
                                "FILE_SUPERSEDE should require DELETE access.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    Name = "notes.txt",
                                    DesiredAccess = 0x80000080U,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.Open,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                    {
                                        new Smb2CreateContext
                                        {
                                            Name = Encoding.ASCII.GetBytes("DH2C"),
                                            Data = new byte[32]
                                        }
                                    })
                                }),
                                "Malformed durable-handle v2 reconnect hints should be rejected when the payload does not match the bounded SMB 3.x wire shape.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2ReadResponseValidator.Validate(new Smb2ReadResponse
                                {
                                    DataBuffer = Array.Empty<byte>(),
                                    DataRemaining = 0,
                                    Flags = 0
                                }),
                                "Successful read responses should not carry an empty data buffer.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2WriteRequestValidator.Validate(new Smb2WriteRequest
                                {
                                    Offset = 0,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Channel = 0,
                                    RemainingBytes = 0,
                                    Flags = Smb2WriteFlags.WriteThrough,
                                    DataBuffer = new byte[] { 0x01 },
                                    WriteChannelInfo = Array.Empty<byte>()
                                }),
                                "Write flags that are not valid for SMB 2.0.2 should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the metadata codec suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor MetadataSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Metadata",
                displayName: "SMB2 metadata codecs and validators",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Metadata",
                        caseId: "MetadataModelsRoundTrip",
                        displayName: "SMB2 metadata models, directory-enumeration payloads, and compound trimming round-trip",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            FileBasicInformation basicInformation = new FileBasicInformation
                            {
                                CreationTime = 0x0102030405060708UL,
                                LastAccessTime = 0x1112131415161718UL,
                                LastWriteTime = 0x2122232425262728UL,
                                ChangeTime = 0x3132333435363738UL,
                                FileAttributes = ProtocolFileAttributes.Hidden | ProtocolFileAttributes.Archive
                            };
                            FileBasicInformation parsedBasicInformation = FileBasicInformation.ReadFrom(basicInformation.ToByteArray());
                            TestAssertions.Equal(basicInformation.CreationTime, parsedBasicInformation.CreationTime, "Unexpected FILE_BASIC_INFORMATION creation time.");
                            TestAssertions.Equal(basicInformation.LastAccessTime, parsedBasicInformation.LastAccessTime, "Unexpected FILE_BASIC_INFORMATION last-access time.");
                            TestAssertions.Equal(basicInformation.LastWriteTime, parsedBasicInformation.LastWriteTime, "Unexpected FILE_BASIC_INFORMATION last-write time.");
                            TestAssertions.Equal(basicInformation.ChangeTime, parsedBasicInformation.ChangeTime, "Unexpected FILE_BASIC_INFORMATION change time.");
                            TestAssertions.Equal(basicInformation.FileAttributes, parsedBasicInformation.FileAttributes, "Unexpected FILE_BASIC_INFORMATION attributes.");

                            FileStandardInformation standardInformation = new FileStandardInformation
                            {
                                AllocationSize = 4096,
                                EndOfFile = 1536,
                                NumberOfLinks = 1,
                                DeletePending = true,
                                Directory = false
                            };
                            FileStandardInformation parsedStandardInformation = FileStandardInformation.ReadFrom(standardInformation.ToByteArray());
                            TestAssertions.Equal(standardInformation.AllocationSize, parsedStandardInformation.AllocationSize, "Unexpected FILE_STANDARD_INFORMATION allocation size.");
                            TestAssertions.Equal(standardInformation.EndOfFile, parsedStandardInformation.EndOfFile, "Unexpected FILE_STANDARD_INFORMATION EOF size.");
                            TestAssertions.True(parsedStandardInformation.DeletePending, "Expected FILE_STANDARD_INFORMATION delete-pending to round-trip.");

                            FileNameInformation fileNameInformation = new FileNameInformation
                            {
                                FileName = "folder\\notes.txt"
                            };
                            FileNameInformation parsedFileNameInformation = FileNameInformation.ReadFrom(fileNameInformation.ToByteArray());
                            TestAssertions.Equal(fileNameInformation.FileName, parsedFileNameInformation.FileName, "Unexpected FILE_NAME_INFORMATION path.");

                            FileNetworkOpenInformation networkOpenInformation = new FileNetworkOpenInformation
                            {
                                CreationTime = basicInformation.CreationTime,
                                LastAccessTime = basicInformation.LastAccessTime,
                                LastWriteTime = basicInformation.LastWriteTime,
                                ChangeTime = basicInformation.ChangeTime,
                                AllocationSize = 8192,
                                EndOfFile = 2048,
                                FileAttributes = ProtocolFileAttributes.ReadOnly
                            };
                            FileNetworkOpenInformation parsedNetworkOpenInformation = FileNetworkOpenInformation.ReadFrom(networkOpenInformation.ToByteArray());
                            TestAssertions.Equal(networkOpenInformation.AllocationSize, parsedNetworkOpenInformation.AllocationSize, "Unexpected FILE_NETWORK_OPEN_INFORMATION allocation size.");
                            TestAssertions.Equal(networkOpenInformation.EndOfFile, parsedNetworkOpenInformation.EndOfFile, "Unexpected FILE_NETWORK_OPEN_INFORMATION EOF size.");
                            TestAssertions.Equal(networkOpenInformation.FileAttributes, parsedNetworkOpenInformation.FileAttributes, "Unexpected FILE_NETWORK_OPEN_INFORMATION attributes.");

                            FileAllInformation allInformation = new FileAllInformation
                            {
                                BasicInformation = basicInformation,
                                StandardInformation = standardInformation,
                                InternalIndexNumber = 0x0102030405060708UL,
                                EaSize = 12,
                                AccessFlags = 0x0012019FU,
                                CurrentByteOffset = 128,
                                Mode = 0,
                                AlignmentRequirement = 0,
                                NameInformation = fileNameInformation
                            };
                            FileAllInformation parsedAllInformation = FileAllInformation.ReadFrom(allInformation.ToByteArray());
                            TestAssertions.Equal(allInformation.BasicInformation.CreationTime, parsedAllInformation.BasicInformation.CreationTime, "Unexpected FILE_ALL_INFORMATION basic creation time.");
                            TestAssertions.Equal(allInformation.StandardInformation.EndOfFile, parsedAllInformation.StandardInformation.EndOfFile, "Unexpected FILE_ALL_INFORMATION EOF size.");
                            TestAssertions.Equal(allInformation.AccessFlags, parsedAllInformation.AccessFlags, "Unexpected FILE_ALL_INFORMATION access mask.");
                            TestAssertions.Equal(allInformation.NameInformation.FileName, parsedAllInformation.NameInformation.FileName, "Unexpected FILE_ALL_INFORMATION name payload.");

                            FileInternalInformation internalInformation = new FileInternalInformation
                            {
                                IndexNumber = 0x1122334455667788UL
                            };
                            FileInternalInformation parsedInternalInformation = FileInternalInformation.ReadFrom(internalInformation.ToByteArray());
                            TestAssertions.Equal(internalInformation.IndexNumber, parsedInternalInformation.IndexNumber, "Unexpected FILE_INTERNAL_INFORMATION index number.");

                            FileFsSizeInformation fileSystemSizeInformation = new FileFsSizeInformation
                            {
                                TotalAllocationUnits = 4096,
                                AvailableAllocationUnits = 3072,
                                SectorsPerAllocationUnit = 8,
                                BytesPerSector = 512
                            };
                            FileFsSizeInformation parsedFileSystemSizeInformation = FileFsSizeInformation.ReadFrom(fileSystemSizeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemSizeInformation.TotalAllocationUnits, parsedFileSystemSizeInformation.TotalAllocationUnits, "Unexpected FILE_FS_SIZE_INFORMATION total allocation units.");
                            TestAssertions.Equal(fileSystemSizeInformation.AvailableAllocationUnits, parsedFileSystemSizeInformation.AvailableAllocationUnits, "Unexpected FILE_FS_SIZE_INFORMATION available allocation units.");
                            TestAssertions.Equal(fileSystemSizeInformation.SectorsPerAllocationUnit, parsedFileSystemSizeInformation.SectorsPerAllocationUnit, "Unexpected FILE_FS_SIZE_INFORMATION sectors per allocation unit.");
                            TestAssertions.Equal(fileSystemSizeInformation.BytesPerSector, parsedFileSystemSizeInformation.BytesPerSector, "Unexpected FILE_FS_SIZE_INFORMATION bytes per sector.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsSizeInformation.ReadFrom(new byte[23]),
                                "Expected truncated FILE_FS_SIZE_INFORMATION payloads to be rejected.");

                            FileFsVolumeInformation fileSystemVolumeInformation = new FileFsVolumeInformation
                            {
                                VolumeCreationTime = 123456789UL,
                                VolumeSerialNumber = 0xA1B2C3D4U,
                                SupportsObjects = false,
                                VolumeLabel = "share"
                            };
                            FileFsVolumeInformation parsedFileSystemVolumeInformation = FileFsVolumeInformation.ReadFrom(fileSystemVolumeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemVolumeInformation.VolumeCreationTime, parsedFileSystemVolumeInformation.VolumeCreationTime, "Unexpected FILE_FS_VOLUME_INFORMATION creation time.");
                            TestAssertions.Equal(fileSystemVolumeInformation.VolumeSerialNumber, parsedFileSystemVolumeInformation.VolumeSerialNumber, "Unexpected FILE_FS_VOLUME_INFORMATION serial number.");
                            TestAssertions.Equal(fileSystemVolumeInformation.VolumeLabel, parsedFileSystemVolumeInformation.VolumeLabel, "Unexpected FILE_FS_VOLUME_INFORMATION label.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsVolumeInformation.ReadFrom(new byte[17]),
                                "Expected truncated FILE_FS_VOLUME_INFORMATION payloads to be rejected.");

                            FileFsAttributeInformation fileSystemAttributeInformation = new FileFsAttributeInformation
                            {
                                FileSystemAttributes = FileSystemAttributesFlags.CasePreservedNames | FileSystemAttributesFlags.UnicodeOnDisk | FileSystemAttributesFlags.PersistentAcls,
                                MaximumComponentNameLength = 255,
                                FileSystemName = "NTFS"
                            };
                            FileFsAttributeInformation parsedFileSystemAttributeInformation = FileFsAttributeInformation.ReadFrom(fileSystemAttributeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemAttributeInformation.FileSystemAttributes, parsedFileSystemAttributeInformation.FileSystemAttributes, "Unexpected FILE_FS_ATTRIBUTE_INFORMATION flags.");
                            TestAssertions.Equal(fileSystemAttributeInformation.MaximumComponentNameLength, parsedFileSystemAttributeInformation.MaximumComponentNameLength, "Unexpected FILE_FS_ATTRIBUTE_INFORMATION maximum component length.");
                            TestAssertions.Equal(fileSystemAttributeInformation.FileSystemName, parsedFileSystemAttributeInformation.FileSystemName, "Unexpected FILE_FS_ATTRIBUTE_INFORMATION filesystem name.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsAttributeInformation.ReadFrom(new byte[11]),
                                "Expected truncated FILE_FS_ATTRIBUTE_INFORMATION payloads to be rejected.");

                            FileFsDeviceInformation fileSystemDeviceInformation = new FileFsDeviceInformation
                            {
                                DeviceType = FileSystemDeviceType.Disk,
                                Characteristics = FileSystemDeviceCharacteristics.RemoteDevice | FileSystemDeviceCharacteristics.DeviceIsMounted
                            };
                            FileFsDeviceInformation parsedFileSystemDeviceInformation = FileFsDeviceInformation.ReadFrom(fileSystemDeviceInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemDeviceInformation.DeviceType, parsedFileSystemDeviceInformation.DeviceType, "Unexpected FILE_FS_DEVICE_INFORMATION device type.");
                            TestAssertions.Equal(fileSystemDeviceInformation.Characteristics, parsedFileSystemDeviceInformation.Characteristics, "Unexpected FILE_FS_DEVICE_INFORMATION characteristics.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsDeviceInformation.ReadFrom(new byte[7]),
                                "Expected truncated FILE_FS_DEVICE_INFORMATION payloads to be rejected.");

                            FileFsFullSizeInformation fileSystemFullSizeInformation = new FileFsFullSizeInformation
                            {
                                TotalAllocationUnits = 4096,
                                CallerAvailableAllocationUnits = 2048,
                                ActualAvailableAllocationUnits = 3072,
                                SectorsPerAllocationUnit = 8,
                                BytesPerSector = 512
                            };
                            FileFsFullSizeInformation parsedFileSystemFullSizeInformation = FileFsFullSizeInformation.ReadFrom(fileSystemFullSizeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemFullSizeInformation.TotalAllocationUnits, parsedFileSystemFullSizeInformation.TotalAllocationUnits, "Unexpected FILE_FS_FULL_SIZE_INFORMATION total allocation units.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.CallerAvailableAllocationUnits, parsedFileSystemFullSizeInformation.CallerAvailableAllocationUnits, "Unexpected FILE_FS_FULL_SIZE_INFORMATION caller available allocation units.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.ActualAvailableAllocationUnits, parsedFileSystemFullSizeInformation.ActualAvailableAllocationUnits, "Unexpected FILE_FS_FULL_SIZE_INFORMATION actual available allocation units.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.SectorsPerAllocationUnit, parsedFileSystemFullSizeInformation.SectorsPerAllocationUnit, "Unexpected FILE_FS_FULL_SIZE_INFORMATION sectors per allocation unit.");
                            TestAssertions.Equal(fileSystemFullSizeInformation.BytesPerSector, parsedFileSystemFullSizeInformation.BytesPerSector, "Unexpected FILE_FS_FULL_SIZE_INFORMATION bytes per sector.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsFullSizeInformation.ReadFrom(new byte[31]),
                                "Expected truncated FILE_FS_FULL_SIZE_INFORMATION payloads to be rejected.");

                            FileFsSectorSizeInformation fileSystemSectorSizeInformation = new FileFsSectorSizeInformation
                            {
                                LogicalBytesPerSector = 512,
                                PhysicalBytesPerSectorForAtomicity = 4096,
                                PhysicalBytesPerSectorForPerformance = 4096,
                                FileSystemEffectivePhysicalBytesPerSectorForAtomicity = 512,
                                Flags = FileSystemSectorSizeFlags.AlignedDevice | FileSystemSectorSizeFlags.PartitionAlignedOnDevice,
                                ByteOffsetForSectorAlignment = 0,
                                ByteOffsetForPartitionAlignment = 0
                            };
                            FileFsSectorSizeInformation parsedFileSystemSectorSizeInformation = FileFsSectorSizeInformation.ReadFrom(fileSystemSectorSizeInformation.ToByteArray());
                            TestAssertions.Equal(fileSystemSectorSizeInformation.LogicalBytesPerSector, parsedFileSystemSectorSizeInformation.LogicalBytesPerSector, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION logical bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.PhysicalBytesPerSectorForAtomicity, parsedFileSystemSectorSizeInformation.PhysicalBytesPerSectorForAtomicity, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION atomicity bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.PhysicalBytesPerSectorForPerformance, parsedFileSystemSectorSizeInformation.PhysicalBytesPerSectorForPerformance, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION performance bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.FileSystemEffectivePhysicalBytesPerSectorForAtomicity, parsedFileSystemSectorSizeInformation.FileSystemEffectivePhysicalBytesPerSectorForAtomicity, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION effective bytes per sector.");
                            TestAssertions.Equal(fileSystemSectorSizeInformation.Flags, parsedFileSystemSectorSizeInformation.Flags, "Unexpected FILE_FS_SECTOR_SIZE_INFORMATION flags.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileFsSectorSizeInformation.ReadFrom(new byte[27]),
                                "Expected truncated FILE_FS_SECTOR_SIZE_INFORMATION payloads to be rejected.");

                            FileAllocationInformation allocationInformation = FileAllocationInformation.ReadFrom(new FileAllocationInformation
                            {
                                AllocationSize = 16384
                            }.ToByteArray());
                            TestAssertions.Equal(16384UL, allocationInformation.AllocationSize, "Unexpected FILE_ALLOCATION_INFORMATION allocation size.");

                            FileEndOfFileInformation endOfFileInformation = FileEndOfFileInformation.ReadFrom(new FileEndOfFileInformation
                            {
                                EndOfFile = 777
                            }.ToByteArray());
                            TestAssertions.Equal(777UL, endOfFileInformation.EndOfFile, "Unexpected FILE_END_OF_FILE_INFORMATION EOF size.");

                            FileDispositionInformation dispositionInformation = FileDispositionInformation.ReadFrom(new FileDispositionInformation
                            {
                                DeletePending = true
                            }.ToByteArray());
                            TestAssertions.True(dispositionInformation.DeletePending, "Expected FILE_DISPOSITION_INFORMATION delete-pending to round-trip.");

                            FileRenameInformationType2 renameInformation = new FileRenameInformationType2
                            {
                                ReplaceIfExists = true,
                                RootDirectory = 0,
                                FileName = "archive\\notes-renamed.txt"
                            };
                            FileRenameInformationType2 parsedRenameInformation = FileRenameInformationType2.ReadFrom(renameInformation.ToByteArray());
                            TestAssertions.True(parsedRenameInformation.ReplaceIfExists, "Expected FILE_RENAME_INFORMATION_TYPE_2 ReplaceIfExists to round-trip.");
                            TestAssertions.Equal(renameInformation.FileName, parsedRenameInformation.FileName, "Unexpected FILE_RENAME_INFORMATION_TYPE_2 path.");

                            byte[] directoryInformationBytes = FileDirectoryInformationEntry.EncodeEntries(new FileDirectoryInformationEntry[]
                            {
                                new FileDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 1,
                                    LastAccessTime = 2,
                                    LastWriteTime = 3,
                                    ChangeTime = 4,
                                    EndOfFile = 5,
                                    AllocationSize = 8,
                                    FileAttributes = ProtocolFileAttributes.Archive,
                                    FileName = "alpha.txt"
                                },
                                new FileDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 10,
                                    LastAccessTime = 11,
                                    LastWriteTime = 12,
                                    ChangeTime = 13,
                                    EndOfFile = 0,
                                    AllocationSize = 0,
                                    FileAttributes = ProtocolFileAttributes.Directory,
                                    FileName = "folder"
                                }
                            });
                            FileDirectoryInformationEntry[] parsedDirectoryEntries = FileDirectoryInformationEntry.DecodeEntries(directoryInformationBytes);
                            TestAssertions.Equal(2, parsedDirectoryEntries.Length, "Expected FILE_DIRECTORY_INFORMATION to round-trip both entries.");
                            TestAssertions.Equal("alpha.txt", parsedDirectoryEntries[0].FileName, "Unexpected first FILE_DIRECTORY_INFORMATION entry name.");
                            TestAssertions.Equal(ProtocolFileAttributes.Directory, parsedDirectoryEntries[1].FileAttributes, "Unexpected second FILE_DIRECTORY_INFORMATION entry attributes.");

                            byte[] fullDirectoryInformationBytes = FileFullDirectoryInformationEntry.EncodeEntries(new FileFullDirectoryInformationEntry[]
                            {
                                new FileFullDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 21,
                                    LastAccessTime = 22,
                                    LastWriteTime = 23,
                                    ChangeTime = 24,
                                    EndOfFile = 25,
                                    AllocationSize = 32,
                                    FileAttributes = ProtocolFileAttributes.Normal,
                                    EaSize = 0,
                                    FileName = "beta.log"
                                }
                            });
                            FileFullDirectoryInformationEntry[] parsedFullDirectoryEntries = FileFullDirectoryInformationEntry.DecodeEntries(fullDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedFullDirectoryEntries.Length, "Expected FILE_FULL_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("beta.log", parsedFullDirectoryEntries[0].FileName, "Unexpected FILE_FULL_DIR_INFORMATION entry name.");
                            TestAssertions.Equal(32UL, parsedFullDirectoryEntries[0].AllocationSize, "Unexpected FILE_FULL_DIR_INFORMATION allocation size.");

                            byte[] bothDirectoryInformationBytes = FileBothDirectoryInformationEntry.EncodeEntries(new FileBothDirectoryInformationEntry[]
                            {
                                new FileBothDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 26,
                                    LastAccessTime = 27,
                                    LastWriteTime = 28,
                                    ChangeTime = 29,
                                    EndOfFile = 30,
                                    AllocationSize = 32,
                                    FileAttributes = ProtocolFileAttributes.Archive,
                                    EaSize = 0,
                                    ShortName = "BETA~1",
                                    FileName = "beta.log"
                                }
                            });
                            FileBothDirectoryInformationEntry[] parsedBothDirectoryEntries = FileBothDirectoryInformationEntry.DecodeEntries(bothDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedBothDirectoryEntries.Length, "Expected FILE_BOTH_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("BETA~1", parsedBothDirectoryEntries[0].ShortName, "Unexpected FILE_BOTH_DIR_INFORMATION short name.");
                            TestAssertions.Equal("beta.log", parsedBothDirectoryEntries[0].FileName, "Unexpected FILE_BOTH_DIR_INFORMATION entry name.");

                            byte[] idBothDirectoryInformationBytes = FileIdBothDirectoryInformationEntry.EncodeEntries(new FileIdBothDirectoryInformationEntry[]
                            {
                                new FileIdBothDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 31,
                                    LastAccessTime = 32,
                                    LastWriteTime = 33,
                                    ChangeTime = 34,
                                    EndOfFile = 35,
                                    AllocationSize = 40,
                                    FileAttributes = ProtocolFileAttributes.Archive,
                                    EaSize = 0,
                                    ShortName = "BETA~1",
                                    FileId = 44,
                                    FileName = "beta.log"
                                }
                            });
                            FileIdBothDirectoryInformationEntry[] parsedIdBothDirectoryEntries = FileIdBothDirectoryInformationEntry.DecodeEntries(idBothDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedIdBothDirectoryEntries.Length, "Expected FILE_ID_BOTH_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("BETA~1", parsedIdBothDirectoryEntries[0].ShortName, "Unexpected FILE_ID_BOTH_DIR_INFORMATION short name.");
                            TestAssertions.Equal(44UL, parsedIdBothDirectoryEntries[0].FileId, "Unexpected FILE_ID_BOTH_DIR_INFORMATION file identifier.");

                            byte[] idFullDirectoryInformationBytes = FileIdFullDirectoryInformationEntry.EncodeEntries(new FileIdFullDirectoryInformationEntry[]
                            {
                                new FileIdFullDirectoryInformationEntry
                                {
                                    FileIndex = 0,
                                    CreationTime = 41,
                                    LastAccessTime = 42,
                                    LastWriteTime = 43,
                                    ChangeTime = 44,
                                    EndOfFile = 45,
                                    AllocationSize = 48,
                                    FileAttributes = ProtocolFileAttributes.Normal,
                                    EaSize = 0,
                                    Reserved = 0,
                                    FileId = 54,
                                    FileName = "gamma.bin"
                                }
                            });
                            FileIdFullDirectoryInformationEntry[] parsedIdFullDirectoryEntries = FileIdFullDirectoryInformationEntry.DecodeEntries(idFullDirectoryInformationBytes);
                            TestAssertions.Equal(1, parsedIdFullDirectoryEntries.Length, "Expected FILE_ID_FULL_DIR_INFORMATION to round-trip a single entry.");
                            TestAssertions.Equal("gamma.bin", parsedIdFullDirectoryEntries[0].FileName, "Unexpected FILE_ID_FULL_DIR_INFORMATION entry name.");
                            TestAssertions.Equal(54UL, parsedIdFullDirectoryEntries[0].FileId, "Unexpected FILE_ID_FULL_DIR_INFORMATION file identifier.");

                            Smb2QueryInfoRequest queryInfoRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.NetworkOpenInformation,
                                OutputBufferLength = 512,
                                AdditionalInformation = 0,
                                Flags = 0,
                                PersistentFileId = 9,
                                VolatileFileId = 10,
                                InputBuffer = Array.Empty<byte>()
                            };
                            byte[] queryInfoRequestBytes = queryInfoRequest.ToByteArray();
                            Smb2QueryInfoRequest parsedQueryInfoRequest = Smb2QueryInfoRequest.ReadFrom(queryInfoRequestBytes);
                            Smb2QueryInfoRequestValidator.Validate(parsedQueryInfoRequest);
                            TestAssertions.Equal(FileInformationClass.NetworkOpenInformation, parsedQueryInfoRequest.FileInfoClass, "Unexpected query-info information class.");
                            TestAssertions.Equal(512U, parsedQueryInfoRequest.OutputBufferLength, "Unexpected query-info output-buffer length.");

                            Smb2QueryInfoRequest allInfoRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.AllInformation,
                                OutputBufferLength = 512,
                                PersistentFileId = 11,
                                VolatileFileId = 12,
                                InputBuffer = Array.Empty<byte>()
                            };
                            Smb2QueryInfoRequest parsedAllInfoRequest = Smb2QueryInfoRequest.ReadFrom(allInfoRequest.ToByteArray());
                            Smb2QueryInfoRequestValidator.Validate(parsedAllInfoRequest);
                            TestAssertions.Equal(FileInformationClass.AllInformation, parsedAllInfoRequest.FileInfoClass, "Unexpected FILE_ALL_INFORMATION query-info class.");

                            Smb2QueryInfoRequest internalInfoRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.InternalInformation,
                                OutputBufferLength = 8,
                                PersistentFileId = 21,
                                VolatileFileId = 22,
                                InputBuffer = Array.Empty<byte>()
                            };
                            Smb2QueryInfoRequest parsedInternalInfoRequest = Smb2QueryInfoRequest.ReadFrom(internalInfoRequest.ToByteArray());
                            Smb2QueryInfoRequestValidator.Validate(parsedInternalInfoRequest);
                            TestAssertions.Equal(FileInformationClass.InternalInformation, parsedInternalInfoRequest.FileInfoClass, "Unexpected FILE_INTERNAL_INFORMATION query-info class.");

                            Smb2QueryInfoRequest fileSystemSizeRequest = new Smb2QueryInfoRequest
                            {
                                InfoType = Smb2InfoType.FileSystem,
                                FileInfoClass = (FileInformationClass)(byte)FileSystemInformationClass.SizeInformation,
                                OutputBufferLength = 512,
                                PersistentFileId = 13,
                                VolatileFileId = 14,
                                InputBuffer = Array.Empty<byte>()
                            };
                            Smb2QueryInfoRequest parsedFileSystemSizeRequest = Smb2QueryInfoRequest.ReadFrom(fileSystemSizeRequest.ToByteArray());
                            Smb2QueryInfoRequestValidator.Validate(parsedFileSystemSizeRequest);
                            TestAssertions.Equal(Smb2InfoType.FileSystem, parsedFileSystemSizeRequest.InfoType, "Unexpected filesystem query-info type.");
                            TestAssertions.Equal((byte)FileSystemInformationClass.SizeInformation, (byte)parsedFileSystemSizeRequest.FileInfoClass, "Unexpected FILE_FS_SIZE_INFORMATION query-info class.");

                            Smb2QueryInfoResponse queryInfoResponse = new Smb2QueryInfoResponse
                            {
                                OutputBuffer = networkOpenInformation.ToByteArray()
                            };
                            byte[] queryInfoResponseBytes = queryInfoResponse.ToByteArray();
                            Smb2QueryInfoResponse parsedQueryInfoResponse = Smb2QueryInfoResponse.ReadFrom(queryInfoResponseBytes);
                            Smb2QueryInfoResponseValidator.Validate(parsedQueryInfoResponse);
                            TestAssertions.SequenceEqual(queryInfoResponse.OutputBuffer, parsedQueryInfoResponse.OutputBuffer, "Unexpected query-info response payload.");

                            Smb2QueryDirectoryRequest queryDirectoryRequest = new Smb2QueryDirectoryRequest
                            {
                                FileInfoClass = FileInformationClass.DirectoryInformation,
                                Flags = Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                FileIndex = 0,
                                PersistentFileId = 11,
                                VolatileFileId = 12,
                                OutputBufferLength = 1024,
                                FileNamePattern = "*.txt"
                            };
                            byte[] queryDirectoryRequestBytes = queryDirectoryRequest.ToByteArray();
                            Smb2QueryDirectoryRequest parsedQueryDirectoryRequest = Smb2QueryDirectoryRequest.ReadFrom(queryDirectoryRequestBytes);
                            Smb2QueryDirectoryRequestValidator.Validate(parsedQueryDirectoryRequest);
                            TestAssertions.Equal(FileInformationClass.DirectoryInformation, parsedQueryDirectoryRequest.FileInfoClass, "Unexpected query-directory information class.");
                            TestAssertions.Equal("*.txt", parsedQueryDirectoryRequest.FileNamePattern, "Unexpected query-directory search pattern.");
                            TestAssertions.Equal(
                                Smb2QueryDirectoryFlags.RestartScans | Smb2QueryDirectoryFlags.ReturnSingleEntry,
                                parsedQueryDirectoryRequest.Flags,
                                "Unexpected query-directory flags.");

                            Smb2QueryDirectoryResponse queryDirectoryResponse = new Smb2QueryDirectoryResponse
                            {
                                OutputBuffer = directoryInformationBytes
                            };
                            byte[] queryDirectoryResponseBytes = queryDirectoryResponse.ToByteArray();
                            Smb2QueryDirectoryResponse parsedQueryDirectoryResponse = Smb2QueryDirectoryResponse.ReadFrom(queryDirectoryResponseBytes);
                            Smb2QueryDirectoryResponseValidator.Validate(parsedQueryDirectoryResponse);
                            TestAssertions.SequenceEqual(queryDirectoryResponse.OutputBuffer, parsedQueryDirectoryResponse.OutputBuffer, "Unexpected query-directory response payload.");

                            Smb2SetInfoRequest setInfoRequest = new Smb2SetInfoRequest
                            {
                                InfoType = Smb2InfoType.File,
                                FileInfoClass = FileInformationClass.RenameInformation,
                                AdditionalInformation = 0,
                                PersistentFileId = 9,
                                VolatileFileId = 10,
                                Buffer = renameInformation.ToByteArray()
                            };
                            byte[] setInfoRequestBytes = setInfoRequest.ToByteArray();
                            Smb2SetInfoRequest parsedSetInfoRequest = Smb2SetInfoRequest.ReadFrom(setInfoRequestBytes);
                            Smb2SetInfoRequestValidator.Validate(parsedSetInfoRequest);
                            TestAssertions.Equal(FileInformationClass.RenameInformation, parsedSetInfoRequest.FileInfoClass, "Unexpected set-info information class.");
                            TestAssertions.SequenceEqual(setInfoRequest.Buffer, parsedSetInfoRequest.Buffer, "Unexpected set-info request buffer.");

                            Smb2SetInfoResponse setInfoResponse = Smb2SetInfoResponse.ReadFrom(new Smb2SetInfoResponse().ToByteArray());
                            Smb2SetInfoResponseValidator.Validate(setInfoResponse);

                            byte[] paddedQueryRequest = new byte[queryInfoRequestBytes.Length + 8];
                            queryInfoRequestBytes.CopyTo(paddedQueryRequest, 0);
                            byte[] trimmedQueryRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.QueryInfo, paddedQueryRequest);
                            TestAssertions.SequenceEqual(queryInfoRequestBytes, trimmedQueryRequest, "Unexpected trimmed compounded query-info request payload.");

                            byte[] paddedQueryResponse = new byte[queryInfoResponseBytes.Length + 8];
                            queryInfoResponseBytes.CopyTo(paddedQueryResponse, 0);
                            byte[] trimmedQueryResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.QueryInfo, paddedQueryResponse);
                            TestAssertions.SequenceEqual(queryInfoResponseBytes, trimmedQueryResponse, "Unexpected trimmed compounded query-info response payload.");

                            byte[] paddedSetRequest = new byte[setInfoRequestBytes.Length + 8];
                            setInfoRequestBytes.CopyTo(paddedSetRequest, 0);
                            byte[] trimmedSetRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.SetInfo, paddedSetRequest);
                            TestAssertions.SequenceEqual(setInfoRequestBytes, trimmedSetRequest, "Unexpected trimmed compounded set-info request payload.");

                            byte[] paddedQueryDirectoryRequest = new byte[queryDirectoryRequestBytes.Length + 8];
                            queryDirectoryRequestBytes.CopyTo(paddedQueryDirectoryRequest, 0);
                            byte[] trimmedQueryDirectoryRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.QueryDirectory, paddedQueryDirectoryRequest);
                            TestAssertions.SequenceEqual(queryDirectoryRequestBytes, trimmedQueryDirectoryRequest, "Unexpected trimmed compounded query-directory request payload.");

                            byte[] paddedQueryDirectoryResponse = new byte[queryDirectoryResponseBytes.Length + 8];
                            queryDirectoryResponseBytes.CopyTo(paddedQueryDirectoryResponse, 0);
                            byte[] trimmedQueryDirectoryResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.QueryDirectory, paddedQueryDirectoryResponse);
                            TestAssertions.SequenceEqual(queryDirectoryResponseBytes, trimmedQueryDirectoryResponse, "Unexpected trimmed compounded query-directory response payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Metadata",
                        caseId: "MetadataValidatorsRejectUnsupportedInputs",
                        displayName: "SMB2 metadata validators reject unsupported info types, malformed FSCC payloads, and non-zero compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryInfoRequestValidator.Validate(new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.Security,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "Security query-info requests should remain unsupported for the current metadata slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryInfoRequestValidator.Validate(new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.NameInformation,
                                    OutputBufferLength = 64,
                                    Flags = 1,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "Query-info flags should remain unsupported for the current metadata slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryInfoRequestValidator.Validate(new Smb2QueryInfoRequest
                                {
                                    InfoType = Smb2InfoType.FileSystem,
                                    FileInfoClass = unchecked((FileInformationClass)0x7F),
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "Filesystem query-info requests should reject unknown information classes.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryDirectoryRequestValidator.Validate(new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    Flags = Smb2QueryDirectoryFlags.IndexSpecified,
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    FileNamePattern = "*"
                                }),
                                "Index-specified query-directory requests should remain unsupported for the current enumeration slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryDirectoryRequestValidator.Validate(new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    OutputBufferLength = 0,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    FileNamePattern = "*"
                                }),
                                "Query-directory requests should require a non-zero output buffer.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2QueryDirectoryRequestValidator.Validate(new Smb2QueryDirectoryRequest
                                {
                                    FileInfoClass = FileInformationClass.DirectoryInformation,
                                    OutputBufferLength = 64,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    FileNamePattern = "folder\\*.txt"
                                }),
                                "Query-directory search patterns should reject path separators.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2SetInfoRequestValidator.Validate(new Smb2SetInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.EndOfFileInformation,
                                    AdditionalInformation = 1,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Buffer = new byte[] { 0x01 }
                                }),
                                "Set-info additional-information flags should remain unsupported for the current metadata slice.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2SetInfoRequestValidator.Validate(new Smb2SetInfoRequest
                                {
                                    InfoType = Smb2InfoType.File,
                                    FileInfoClass = FileInformationClass.BasicInformation,
                                    PersistentFileId = 0,
                                    VolatileFileId = 0,
                                    Buffer = new byte[] { 0x01 }
                                }),
                                "Set-info requests should require a file identifier pair.");

                            byte[] invalidStandardInformation = new FileStandardInformation
                            {
                                AllocationSize = 1,
                                EndOfFile = 1,
                                NumberOfLinks = 1,
                                DeletePending = false,
                                Directory = false
                            }.ToByteArray();
                            invalidStandardInformation[20] = 2;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileStandardInformation.ReadFrom(invalidStandardInformation),
                                "FILE_STANDARD_INFORMATION should reject invalid Boolean fields.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileNameInformation.ReadFrom(new byte[] { 0x03, 0x00, 0x00, 0x00, 0x41, 0x00, 0x42 }),
                                "FILE_NAME_INFORMATION should reject odd UTF-16 lengths.");

                            byte[] invalidDirectoryInformation = FileDirectoryInformationEntry.EncodeEntries(new FileDirectoryInformationEntry[]
                            {
                                new FileDirectoryInformationEntry
                                {
                                    FileName = "odd.txt"
                                }
                            });
                            invalidDirectoryInformation[60] = 0x03;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileDirectoryInformationEntry.DecodeEntries(invalidDirectoryInformation),
                                "FILE_DIRECTORY_INFORMATION should reject odd UTF-16 file-name lengths.");

                            byte[] invalidBothDirectoryInformation = FileBothDirectoryInformationEntry.EncodeEntries(new FileBothDirectoryInformationEntry[]
                            {
                                new FileBothDirectoryInformationEntry
                                {
                                    FileName = "odd.txt"
                                }
                            });
                            invalidBothDirectoryInformation[60] = 0x03;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileBothDirectoryInformationEntry.DecodeEntries(invalidBothDirectoryInformation),
                                "FILE_BOTH_DIR_INFORMATION should reject odd UTF-16 file-name lengths.");

                            byte[] invalidRenameInformation = new FileRenameInformationType2
                            {
                                ReplaceIfExists = false,
                                RootDirectory = 0,
                                FileName = "renamed.txt"
                            }.ToByteArray();
                            invalidRenameInformation[0] = 2;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileRenameInformationType2.ReadFrom(invalidRenameInformation),
                                "FILE_RENAME_INFORMATION_TYPE_2 should reject invalid ReplaceIfExists values.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => FileDispositionInformation.ReadFrom(new byte[] { 0x02 }),
                                "FILE_DISPOSITION_INFORMATION should reject invalid delete-pending values.");

                            byte[] paddedSetResponse = new byte[3];
                            new Smb2SetInfoResponse().ToByteArray().CopyTo(paddedSetResponse, 0);
                            paddedSetResponse[2] = 0x7F;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.SetInfo, paddedSetResponse),
                                "Compounded set-info responses should reject non-zero trailing padding.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 durable-handle create-context suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2DurableHandleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Durable",
                displayName: "SMB2 durable-handle create contexts",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Durable",
                        caseId: "DurableCreateContextsRoundTripAndValidate",
                        displayName: "Durable create request, reconnect, and response contexts round-trip and validate",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest durableRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    Smb2DurableHandleRequestContext.Create()
                                })
                            };
                            Smb2CreateRequestValidator.Validate(durableRequest);
                            Smb2CreateRequest parsedDurableRequest = Smb2CreateRequest.ReadFrom(durableRequest.ToByteArray());
                            Smb2CreateContext[] durableRequestContexts = Smb2CreateContextCodec.Decode(parsedDurableRequest.CreateContexts);
                            TestAssertions.Equal(1, durableRequestContexts.Length, "Expected one durable request context.");
                            TestAssertions.True(Smb2DurableHandleRequestContext.IsMatch(durableRequestContexts[0]), "Expected the request context to be DHnQ.");

                            Smb2DurableHandleReconnectContext reconnectContext = new Smb2DurableHandleReconnectContext
                            {
                                PersistentFileId = 7,
                                VolatileFileId = 11
                            };
                            Smb2CreateRequest reconnectRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    reconnectContext.ToCreateContext()
                                })
                            };
                            Smb2CreateRequestValidator.Validate(reconnectRequest);
                            Smb2CreateRequest parsedReconnectRequest = Smb2CreateRequest.ReadFrom(reconnectRequest.ToByteArray());
                            Smb2CreateContext[] reconnectRequestContexts = Smb2CreateContextCodec.Decode(parsedReconnectRequest.CreateContexts);
                            TestAssertions.Equal(1, reconnectRequestContexts.Length, "Expected one durable reconnect context.");
                            Smb2DurableHandleReconnectContext parsedReconnectContext = Smb2DurableHandleReconnectContext.ReadFrom(reconnectRequestContexts[0]);
                            TestAssertions.Equal(7UL, parsedReconnectContext.PersistentFileId, "Unexpected durable reconnect persistent file identifier.");
                            TestAssertions.Equal(11UL, parsedReconnectContext.VolatileFileId, "Unexpected durable reconnect volatile file identifier.");

                            Smb2CreateResponse durableResponse = new Smb2CreateResponse
                            {
                                OplockLevel = Smb2OplockLevel.Batch,
                                CreateAction = Smb2CreateAction.Opened,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                PersistentFileId = 7,
                                VolatileFileId = 13,
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    Smb2DurableHandleResponseContext.Create()
                                })
                            };
                            Smb2CreateResponseValidator.Validate(durableResponse);
                            Smb2CreateResponse parsedDurableResponse = Smb2CreateResponse.ReadFrom(durableResponse.ToByteArray());
                            Smb2CreateContext[] durableResponseContexts = Smb2CreateContextCodec.Decode(parsedDurableResponse.CreateContexts);
                            TestAssertions.Equal(1, durableResponseContexts.Length, "Expected one durable response context.");
                            Smb2DurableHandleResponseContext.Validate(durableResponseContexts[0]);

                            byte[] paddedResponseContexts = new byte[parsedDurableResponse.CreateContexts.Length + 8];
                            Buffer.BlockCopy(parsedDurableResponse.CreateContexts, 0, paddedResponseContexts, 0, parsedDurableResponse.CreateContexts.Length);
                            Smb2CreateContext[] paddedDurableResponseContexts = Smb2CreateContextCodec.Decode(paddedResponseContexts);
                            TestAssertions.Equal(1, paddedDurableResponseContexts.Length, "Expected the durable create-context decoder to tolerate trailing zero padding after the final context.");

                            LittleEndianWriter windowsStyleContextWriter = new LittleEndianWriter();
                            windowsStyleContextWriter.WriteUInt32(0);
                            windowsStyleContextWriter.WriteUInt16(16);
                            windowsStyleContextWriter.WriteUInt16(4);
                            windowsStyleContextWriter.WriteUInt16(0);
                            windowsStyleContextWriter.WriteUInt16(24);
                            windowsStyleContextWriter.WriteUInt32(0);
                            windowsStyleContextWriter.WriteBytes(Encoding.ASCII.GetBytes("MxAc"));

                            while (windowsStyleContextWriter.Length < 24)
                            {
                                windowsStyleContextWriter.WriteByte(0);
                            }

                            Smb2CreateContext[] windowsStyleContexts = Smb2CreateContextCodec.Decode(windowsStyleContextWriter.ToArray());
                            TestAssertions.Equal(1, windowsStyleContexts.Length, "Expected the durable create-context decoder to accept zero-length Windows-style create contexts that carry a padded data offset.");
                            TestAssertions.Equal("MxAc", Encoding.ASCII.GetString(windowsStyleContexts[0].Name), "Unexpected Windows-style create-context name.");
                            TestAssertions.Equal(0, windowsStyleContexts[0].Data.Length, "Expected the Windows-style create context to preserve an empty payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Durable",
                        caseId: "DurableCreateContextValidationRejectsMalformedAndUnsupportedContexts",
                        displayName: "Durable create-context validation rejects malformed, duplicate, and durable reconnect contexts",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2CreateRequest malformedRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = new byte[] { 0x01, 0x02, 0x03 }
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(malformedRequest),
                                "Expected malformed durable create-context buffers to be rejected.");

                            Smb2CreateRequest duplicateDurableRequest = new Smb2CreateRequest
                            {
                                RequestedOplockLevel = Smb2OplockLevel.Batch,
                                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                DesiredAccess = 0xC0010000U,
                                FileAttributes = ProtocolFileAttributes.Normal,
                                ShareAccess = 0x00000007U,
                                CreateDisposition = Smb2CreateDisposition.Open,
                                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                Name = "docs\\sample.txt",
                                CreateContexts = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                                {
                                    Smb2DurableHandleRequestContext.Create(),
                                    Smb2DurableHandleRequestContext.Create()
                                })
                            };
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(duplicateDurableRequest),
                                "Expected duplicate durable-handle request contexts to be rejected.");

                            byte[] durableRequestBytes = Smb2CreateContextCodec.Encode(new Smb2CreateContext[]
                            {
                                Smb2DurableHandleRequestContext.Create()
                            });
                            byte[] malformedTrailingContextBytes = new byte[durableRequestBytes.Length + 8];
                            Buffer.BlockCopy(durableRequestBytes, 0, malformedTrailingContextBytes, 0, durableRequestBytes.Length);
                            malformedTrailingContextBytes[durableRequestBytes.Length] = 0x7F;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CreateContextCodec.Decode(malformedTrailingContextBytes),
                                "Expected the durable create-context decoder to reject non-zero trailing bytes after the final context.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 locking suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2LockSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Locking",
                displayName: "SMB2 byte-range lock messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Locking",
                        caseId: "LockMessagesRoundTrip",
                        displayName: "SMB2 lock messages round-trip and trim compounded padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2LockRequest lockRequest = new Smb2LockRequest
                            {
                                LockSequence = 0,
                                PersistentFileId = 91,
                                VolatileFileId = 92,
                                Locks = new Smb2LockElement[]
                                {
                                    new Smb2LockElement
                                    {
                                        Offset = 128,
                                        Length = 64,
                                        Flags = Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately
                                    }
                                }
                            };
                            byte[] lockRequestBytes = lockRequest.ToByteArray();
                            Smb2LockRequest parsedLockRequest = Smb2LockRequest.ReadFrom(lockRequestBytes);
                            Smb2LockRequestValidator.Validate(parsedLockRequest);
                            TestAssertions.Equal(1, parsedLockRequest.Locks.Length, "Expected a single parsed lock element.");
                            TestAssertions.Equal(128UL, parsedLockRequest.Locks[0].Offset, "Unexpected lock-element offset.");
                            TestAssertions.Equal(64UL, parsedLockRequest.Locks[0].Length, "Unexpected lock-element length.");
                            TestAssertions.Equal(
                                Smb2LockFlags.ExclusiveLock | Smb2LockFlags.FailImmediately,
                                parsedLockRequest.Locks[0].Flags,
                                "Unexpected lock-element flags.");

                            Smb2LockResponse lockResponse = Smb2LockResponse.ReadFrom(new Smb2LockResponse().ToByteArray());
                            Smb2LockResponseValidator.Validate(lockResponse);

                            byte[] paddedLockRequest = new byte[lockRequestBytes.Length + 8];
                            lockRequestBytes.CopyTo(paddedLockRequest, 0);
                            byte[] trimmedLockRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Lock, paddedLockRequest);
                            TestAssertions.SequenceEqual(lockRequestBytes, trimmedLockRequest, "Unexpected trimmed compounded lock request payload.");

                            byte[] lockResponseBytes = new Smb2LockResponse().ToByteArray();
                            byte[] paddedLockResponse = new byte[lockResponseBytes.Length + 8];
                            lockResponseBytes.CopyTo(paddedLockResponse, 0);
                            byte[] trimmedLockResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Lock, paddedLockResponse);
                            TestAssertions.SequenceEqual(lockResponseBytes, trimmedLockResponse, "Unexpected trimmed compounded lock response payload.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Locking",
                        caseId: "LockValidatorsRejectUnsupportedInputs",
                        displayName: "SMB2 lock validators reject malformed ranges and unsupported flag combinations",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    LockSequence = 1,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 1,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    }
                                }),
                                "SMB2.0.2 lock requests should reject non-zero lock-sequence values.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = Array.Empty<Smb2LockElement>()
                                }),
                                "Lock requests should require at least one lock element.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 0,
                                            Flags = Smb2LockFlags.ExclusiveLock
                                        }
                                    }
                                }),
                                "Lock requests should reject zero-length ranges.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 8,
                                            Flags = Smb2LockFlags.SharedLock | Smb2LockFlags.ExclusiveLock
                                        }
                                    }
                                }),
                                "Lock requests should reject conflicting shared and exclusive flags.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LockRequestValidator.Validate(new Smb2LockRequest
                                {
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    Locks = new Smb2LockElement[]
                                    {
                                        new Smb2LockElement
                                        {
                                            Offset = 0,
                                            Length = 8,
                                            Flags = Smb2LockFlags.Unlock | Smb2LockFlags.FailImmediately
                                        }
                                    }
                                }),
                                "Unlock lock elements should reject lock-acquisition flags.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LockElement.ReadFrom(new byte[23]),
                                "A truncated SMB2 lock element should fail to parse.");

                            byte[] malformedLockRequestBytes = new Smb2LockRequest
                            {
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                Locks = new Smb2LockElement[]
                                {
                                    new Smb2LockElement
                                    {
                                        Offset = 0,
                                        Length = 8,
                                        Flags = Smb2LockFlags.ExclusiveLock
                                    }
                                }
                            }.ToByteArray();
                            malformedLockRequestBytes[2] = 0x02;
                            malformedLockRequestBytes[3] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LockRequest.ReadFrom(malformedLockRequestBytes),
                                "SMB2 lock requests should reject buffers whose encoded lock count exceeds the available payload.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 oplock-break suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2OplockBreakSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2OplockBreak",
                displayName: "SMB2 oplock-break messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2OplockBreak",
                        caseId: "OplockBreakMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 oplock-break messages round-trip and trim compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            };
                            byte[] notificationBytes = notification.ToByteArray();
                            Smb2OplockBreakNotification parsedNotification = Smb2OplockBreakNotification.ReadFrom(notificationBytes);
                            Smb2OplockBreakNotificationValidator.Validate(parsedNotification);
                            TestAssertions.Equal(Smb2OplockLevel.None, parsedNotification.OplockLevel, "Unexpected oplock-break notification level.");
                            TestAssertions.Equal(17UL, parsedNotification.PersistentFileId, "Unexpected oplock-break notification persistent file identifier.");
                            TestAssertions.Equal(18UL, parsedNotification.VolatileFileId, "Unexpected oplock-break notification volatile file identifier.");

                            Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            };
                            byte[] acknowledgmentBytes = acknowledgment.ToByteArray();
                            Smb2OplockBreakAcknowledgment parsedAcknowledgment = Smb2OplockBreakAcknowledgment.ReadFrom(acknowledgmentBytes);
                            Smb2OplockBreakAcknowledgmentValidator.Validate(parsedAcknowledgment);
                            byte[] trimmedAcknowledgment = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.OplockBreak, Combine(acknowledgmentBytes, new byte[4]));
                            TestAssertions.SequenceEqual(acknowledgmentBytes, trimmedAcknowledgment, "Unexpected compounded SMB2 oplock-break acknowledgment trimming result.");

                            Smb2OplockBreakResponse response = new Smb2OplockBreakResponse
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb2OplockBreakResponse parsedResponse = Smb2OplockBreakResponse.ReadFrom(responseBytes);
                            Smb2OplockBreakResponseValidator.Validate(parsedResponse);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.OplockBreak, Combine(responseBytes, new byte[4]));
                            TestAssertions.SequenceEqual(responseBytes, trimmedResponse, "Unexpected compounded SMB2 oplock-break response trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2OplockBreak",
                        caseId: "OplockBreakMessagesRejectMalformedInputs",
                        displayName: "SMB2 oplock-break messages reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] malformedNotification = new Smb2OplockBreakNotification
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            }.ToByteArray();
                            malformedNotification[0] = 0x17;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2OplockBreakNotification.ReadFrom(malformedNotification),
                                "Malformed SMB2 oplock-break notifications should be rejected.");

                            byte[] malformedAcknowledgment = new Smb2OplockBreakAcknowledgment
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            }.ToByteArray();
                            malformedAcknowledgment[0] = 0x17;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2OplockBreakAcknowledgment.ReadFrom(malformedAcknowledgment),
                                "Malformed SMB2 oplock-break acknowledgments should be rejected.");

                            byte[] malformedResponse = new Smb2OplockBreakResponse
                            {
                                OplockLevel = Smb2OplockLevel.None,
                                PersistentFileId = 17,
                                VolatileFileId = 18
                            }.ToByteArray();
                            malformedResponse[0] = 0x17;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2OplockBreakResponse.ReadFrom(malformedResponse),
                                "Malformed SMB2 oplock-break responses should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakNotificationValidator.Validate(null!),
                                "A null SMB2 oplock-break notification should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakAcknowledgmentValidator.Validate(null!),
                                "A null SMB2 oplock-break acknowledgment should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakResponseValidator.Validate(null!),
                                "A null SMB2 oplock-break response should fail validation.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakNotificationValidator.Validate(new Smb2OplockBreakNotification
                                {
                                    OplockLevel = Smb2OplockLevel.Batch,
                                    PersistentFileId = 17,
                                    VolatileFileId = 18
                                }),
                                "Unsupported bounded oplock levels should be rejected for unsolicited oplock-break notifications.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakAcknowledgmentValidator.Validate(new Smb2OplockBreakAcknowledgment
                                {
                                    OplockLevel = Smb2OplockLevel.Lease,
                                    PersistentFileId = 17,
                                    VolatileFileId = 18
                                }),
                                "Unsupported bounded oplock levels should be rejected for oplock-break acknowledgments.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2OplockBreakResponseValidator.Validate(new Smb2OplockBreakResponse
                                {
                                    OplockLevel = Smb2OplockLevel.None,
                                    PersistentFileId = 0,
                                    VolatileFileId = 0
                                }),
                                "SMB2 oplock-break responses without tracked file identifiers should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 lease suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2LeaseSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Lease",
                displayName: "SMB2 lease messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Lease",
                        caseId: "LeaseContextsAndBreakMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 lease contexts and break messages round-trip and trim compound padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] leaseKey = new byte[16];

                            for (int index = 0; index < leaseKey.Length; index++)
                            {
                                leaseKey[index] = (byte)(index + 1);
                            }

                            Smb2CreateRequestLeaseContext requestContext = new Smb2CreateRequestLeaseContext
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                            };
                            Smb2CreateRequestLeaseContext parsedRequestContext = Smb2CreateRequestLeaseContext.ReadFrom(requestContext.ToCreateContext());
                            TestAssertions.SequenceEqual(leaseKey, parsedRequestContext.LeaseKey, "Unexpected SMB2 lease request context lease key.");
                            TestAssertions.Equal(requestContext.LeaseState, parsedRequestContext.LeaseState, "Unexpected SMB2 lease request context lease state.");

                            Smb2CreateResponseLeaseContext responseContext = new Smb2CreateResponseLeaseContext
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching,
                                LeaseFlags = Smb2LeaseFlags.BreakInProgress
                            };
                            Smb2CreateResponseLeaseContext parsedResponseContext = Smb2CreateResponseLeaseContext.ReadFrom(responseContext.ToCreateContext());
                            TestAssertions.SequenceEqual(leaseKey, parsedResponseContext.LeaseKey, "Unexpected SMB2 lease response context lease key.");
                            TestAssertions.Equal(responseContext.LeaseState, parsedResponseContext.LeaseState, "Unexpected SMB2 lease response context lease state.");
                            TestAssertions.Equal(responseContext.LeaseFlags, parsedResponseContext.LeaseFlags, "Unexpected SMB2 lease response context flags.");

                            Smb2LeaseBreakNotification notification = new Smb2LeaseBreakNotification
                            {
                                Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                                LeaseKey = leaseKey,
                                CurrentLeaseState = Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching,
                                NewLeaseState = Smb2LeaseState.None
                            };
                            byte[] notificationBytes = notification.ToByteArray();
                            Smb2LeaseBreakNotification parsedNotification = Smb2LeaseBreakNotification.ReadFrom(notificationBytes);
                            Smb2LeaseBreakNotificationValidator.Validate(parsedNotification);
                            TestAssertions.Equal(notification.CurrentLeaseState, parsedNotification.CurrentLeaseState, "Unexpected SMB2 lease-break notification current state.");
                            TestAssertions.Equal(notification.NewLeaseState, parsedNotification.NewLeaseState, "Unexpected SMB2 lease-break notification new state.");
                            byte[] trimmedNotification = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.OplockBreak, Combine(notificationBytes, new byte[4]));
                            TestAssertions.SequenceEqual(notificationBytes, trimmedNotification, "Unexpected compounded SMB2 lease-break notification trimming result.");

                            Smb2LeaseBreakAcknowledgment acknowledgment = new Smb2LeaseBreakAcknowledgment
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.None
                            };
                            byte[] acknowledgmentBytes = acknowledgment.ToByteArray();
                            Smb2LeaseBreakAcknowledgment parsedAcknowledgment = Smb2LeaseBreakAcknowledgment.ReadFrom(acknowledgmentBytes);
                            Smb2LeaseBreakAcknowledgmentValidator.Validate(parsedAcknowledgment);
                            byte[] trimmedAcknowledgment = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.OplockBreak, Combine(acknowledgmentBytes, new byte[4]));
                            TestAssertions.SequenceEqual(acknowledgmentBytes, trimmedAcknowledgment, "Unexpected compounded SMB2 lease-break acknowledgment trimming result.");

                            Smb2LeaseBreakResponse response = new Smb2LeaseBreakResponse
                            {
                                LeaseKey = leaseKey,
                                LeaseState = Smb2LeaseState.None
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb2LeaseBreakResponse parsedResponse = Smb2LeaseBreakResponse.ReadFrom(responseBytes);
                            Smb2LeaseBreakResponseValidator.Validate(parsedResponse);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.OplockBreak, Combine(responseBytes, new byte[4]));
                            TestAssertions.SequenceEqual(responseBytes, trimmedResponse, "Unexpected compounded SMB2 lease-break response trimming result.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Lease",
                        caseId: "LeaseContextsAndBreakMessagesRejectMalformedInputs",
                        displayName: "SMB2 lease contexts and break messages reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestLeaseContext.Validate(new Smb2CreateRequestLeaseContext
                                {
                                    LeaseKey = new byte[16],
                                    LeaseState = (Smb2LeaseState)0x80
                                }),
                                "Unsupported SMB2 lease request state bits should be rejected.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateResponseLeaseContext.Validate(new Smb2CreateResponseLeaseContext
                                {
                                    LeaseKey = new byte[16],
                                    LeaseState = Smb2LeaseState.ReadCaching,
                                    LeaseFlags = (Smb2LeaseFlags)0x80
                                }),
                                "Unsupported SMB2 lease response flags should be rejected.");

                            byte[] malformedNotification = new Smb2LeaseBreakNotification
                            {
                                LeaseKey = new byte[16],
                                CurrentLeaseState = Smb2LeaseState.ReadCaching,
                                NewLeaseState = Smb2LeaseState.None
                            }.ToByteArray();
                            malformedNotification[0] = 0x2B;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2LeaseBreakNotification.ReadFrom(malformedNotification),
                                "Malformed SMB2 lease-break notifications should be rejected.");

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LeaseBreakAcknowledgmentValidator.Validate(new Smb2LeaseBreakAcknowledgment
                                {
                                    LeaseKey = new byte[8],
                                    LeaseState = Smb2LeaseState.None
                                }),
                                "Malformed SMB2 lease-break acknowledgment lease keys should be rejected.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2LeaseBreakResponseValidator.Validate(new Smb2LeaseBreakResponse
                                {
                                    LeaseKey = new byte[16],
                                    LeaseState = (Smb2LeaseState)0x80
                                }),
                                "Unsupported SMB2 lease-break response lease states should be rejected.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2CreateRequestValidator.Validate(new Smb2CreateRequest
                                {
                                    RequestedOplockLevel = Smb2OplockLevel.Lease,
                                    ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                                    DesiredAccess = 0x80000000U,
                                    FileAttributes = ProtocolFileAttributes.Normal,
                                    ShareAccess = 0x00000007U,
                                    CreateDisposition = Smb2CreateDisposition.OpenIf,
                                    CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                                    Name = "dup.txt",
                                    CreateContexts = Smb2CreateContextCodec.Encode(new[]
                                    {
                                        new Smb2CreateRequestLeaseContext
                                        {
                                            LeaseKey = new byte[16],
                                            LeaseState = Smb2LeaseState.ReadCaching
                                        }.ToCreateContext(),
                                        new Smb2CreateRequestLeaseContext
                                        {
                                            LeaseKey = new byte[16],
                                            LeaseState = Smb2LeaseState.ReadCaching
                                        }.ToCreateContext()
                                    })
                                }),
                                "Duplicate SMB2 lease request contexts should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the SMB2 IOCTL suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor Smb2IoctlSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Smb2Ioctl",
                displayName: "SMB2 IOCTL messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Ioctl",
                        caseId: "IoctlMessagesRoundTripAndTrimCompoundPadding",
                        displayName: "SMB2 IOCTL messages round-trip and trim compounded zero padding",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Smb2IoctlRequest request = new Smb2IoctlRequest
                            {
                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                PersistentFileId = 301,
                                VolatileFileId = 302,
                                MaxInputResponse = 0,
                                MaxOutputResponse = 4096,
                                Flags = Smb2IoctlFlags.IsFsctl,
                                InputBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 }
                            };
                            byte[] requestBytes = request.ToByteArray();
                            Smb2IoctlRequest parsedRequest = Smb2IoctlRequest.ReadFrom(requestBytes);
                            Smb2IoctlRequestValidator.Validate(parsedRequest);
                            TestAssertions.Equal((uint)FsctlCode.SrvEnumerateSnapshots, parsedRequest.CtlCode, "Unexpected IOCTL control code.");
                            TestAssertions.Equal(301UL, parsedRequest.PersistentFileId, "Unexpected IOCTL persistent file identifier.");
                            TestAssertions.Equal(302UL, parsedRequest.VolatileFileId, "Unexpected IOCTL volatile file identifier.");
                            TestAssertions.SequenceEqual(request.InputBuffer, parsedRequest.InputBuffer, "Unexpected IOCTL input buffer.");

                            byte[] paddedRequest = Combine(requestBytes, new byte[8]);
                            byte[] trimmedRequest = Smb2CompoundPayloadHelper.TrimRequestPayload(Smb2Command.Ioctl, paddedRequest);
                            TestAssertions.SequenceEqual(requestBytes, trimmedRequest, "Unexpected compounded IOCTL request trimming result.");

                            Smb2IoctlResponse response = new Smb2IoctlResponse
                            {
                                CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                PersistentFileId = UInt64.MaxValue,
                                VolatileFileId = UInt64.MaxValue,
                                InputBuffer = new byte[] { 0xAA, 0xBB, 0xCC },
                                OutputBuffer = new byte[] { 0x41, 0x42, 0x43, 0x44 },
                                Flags = 0
                            };
                            byte[] responseBytes = response.ToByteArray();
                            Smb2IoctlResponse parsedResponse = Smb2IoctlResponse.ReadFrom(responseBytes);
                            Smb2IoctlResponseValidator.Validate(parsedResponse);
                            TestAssertions.Equal((uint)FsctlCode.QueryNetworkInterfaceInfo, parsedResponse.CtlCode, "Unexpected IOCTL response control code.");
                            TestAssertions.SequenceEqual(response.InputBuffer, parsedResponse.InputBuffer, "Unexpected IOCTL response input buffer.");
                            TestAssertions.SequenceEqual(response.OutputBuffer, parsedResponse.OutputBuffer, "Unexpected IOCTL response output buffer.");
                            TestAssertions.SequenceEqual(responseBytes, parsedResponse.ToByteArray(), "The SMB2 IOCTL response encoding changed.");

                            byte[] paddedResponse = Combine(responseBytes, new byte[8]);
                            byte[] trimmedResponse = Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Ioctl, paddedResponse);
                            TestAssertions.SequenceEqual(responseBytes, trimmedResponse, "Unexpected compounded IOCTL response trimming result.");

                            SrvSnapshotArray snapshotArray = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 2,
                                Snapshots = new string[]
                                {
                                    "@GMT-2025.01.02-03.04.05",
                                    "@GMT-2025.06.07-08.09.10"
                                }
                            };
                            byte[] snapshotArrayBytes = snapshotArray.ToByteArray();
                            SrvSnapshotArray parsedSnapshotArray = SrvSnapshotArray.ReadFrom(snapshotArrayBytes);
                            TestAssertions.Equal(2U, parsedSnapshotArray.NumberOfSnapshots, "Unexpected snapshot-array total count.");
                            TestAssertions.Equal(2, parsedSnapshotArray.Snapshots.Length, "Unexpected snapshot-array returned count.");
                            TestAssertions.Equal("@GMT-2025.01.02-03.04.05", parsedSnapshotArray.Snapshots[0], "Unexpected first snapshot token.");
                            TestAssertions.Equal("@GMT-2025.06.07-08.09.10", parsedSnapshotArray.Snapshots[1], "Unexpected second snapshot token.");

                            SrvSnapshotArray emptySnapshotArray = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 0,
                                Snapshots = Array.Empty<string>()
                            };
                            byte[] emptySnapshotArrayBytes = emptySnapshotArray.ToByteArray();
                            SrvSnapshotArray parsedEmptySnapshotArray = SrvSnapshotArray.ReadFrom(emptySnapshotArrayBytes);
                            TestAssertions.Equal(0U, parsedEmptySnapshotArray.NumberOfSnapshots, "Unexpected empty snapshot-array total count.");
                            TestAssertions.Equal(0, parsedEmptySnapshotArray.Snapshots.Length, "Expected empty snapshot arrays to decode without tokens.");

                            ValidateNegotiateInfoRequest validateRequest = new ValidateNegotiateInfoRequest
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ClientGuid = Guid.Parse("9B3FD6EF-0A95-4C70-9010-6C37083384F0"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
                            };
                            byte[] validateRequestBytes = validateRequest.ToByteArray();
                            ValidateNegotiateInfoRequest parsedValidateRequest = ValidateNegotiateInfoRequest.ReadFrom(validateRequestBytes);
                            TestAssertions.Equal(validateRequest.Capabilities, parsedValidateRequest.Capabilities, "Unexpected VALIDATE_NEGOTIATE_INFO request capabilities.");
                            TestAssertions.Equal(validateRequest.ClientGuid, parsedValidateRequest.ClientGuid, "Unexpected VALIDATE_NEGOTIATE_INFO request GUID.");
                            TestAssertions.Equal(validateRequest.SecurityMode, parsedValidateRequest.SecurityMode, "Unexpected VALIDATE_NEGOTIATE_INFO request security mode.");
                            TestAssertions.Equal(2, parsedValidateRequest.Dialects.Length, "Unexpected VALIDATE_NEGOTIATE_INFO request dialect count.");
                            TestAssertions.Equal(SmbDialect.Smb2002, parsedValidateRequest.Dialects[0], "Unexpected first VALIDATE_NEGOTIATE_INFO request dialect.");
                            TestAssertions.Equal(SmbDialect.Smb21, parsedValidateRequest.Dialects[1], "Unexpected second VALIDATE_NEGOTIATE_INFO request dialect.");

                            ValidateNegotiateInfoResponse validateResponse = new ValidateNegotiateInfoResponse
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ServerGuid = Guid.Parse("18E0CDBA-F663-4BF3-B328-A365A8449750"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb2002
                            };
                            byte[] validateResponseBytes = validateResponse.ToByteArray();
                            ValidateNegotiateInfoResponse parsedValidateResponse = ValidateNegotiateInfoResponse.ReadFrom(validateResponseBytes);
                            TestAssertions.Equal(validateResponse.Capabilities, parsedValidateResponse.Capabilities, "Unexpected VALIDATE_NEGOTIATE_INFO response capabilities.");
                            TestAssertions.Equal(validateResponse.ServerGuid, parsedValidateResponse.ServerGuid, "Unexpected VALIDATE_NEGOTIATE_INFO response GUID.");
                            TestAssertions.Equal(validateResponse.SecurityMode, parsedValidateResponse.SecurityMode, "Unexpected VALIDATE_NEGOTIATE_INFO response security mode.");
                            TestAssertions.Equal(validateResponse.Dialect, parsedValidateResponse.Dialect, "Unexpected VALIDATE_NEGOTIATE_INFO response dialect.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Smb2Ioctl",
                        caseId: "IoctlValidatorsRejectUnsupportedInputs",
                        displayName: "SMB2 IOCTL validators reject malformed identifiers, flags, and payload shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(null!),
                                "A null SMB2 IOCTL request should fail validation.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(new Smb2IoctlRequest
                                {
                                    CtlCode = 0,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "SMB2 IOCTL requests should require a non-zero control code.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(new Smb2IoctlRequest
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "SMB2 IOCTL requests should reject partial wildcard file identifiers.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlRequestValidator.Validate(new Smb2IoctlRequest
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = 0,
                                    VolatileFileId = 0,
                                    InputBuffer = Array.Empty<byte>()
                                }),
                                "SMB2 IOCTL requests should require a concrete or wildcard file identifier pair.");
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb2IoctlResponseValidator.Validate(new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                    PersistentFileId = UInt64.MaxValue,
                                    VolatileFileId = UInt64.MaxValue,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = Array.Empty<byte>(),
                                    Flags = 1
                                }),
                                "SMB2 IOCTL responses should reject non-zero reserved flags.");

                            byte[] malformedRequestBytes = new Smb2IoctlRequest
                            {
                                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                PersistentFileId = 1,
                                VolatileFileId = 2,
                                MaxOutputResponse = 256,
                                Flags = Smb2IoctlFlags.IsFsctl,
                                InputBuffer = Array.Empty<byte>()
                            }.ToByteArray();
                            malformedRequestBytes[40] = 0x01;
                            malformedRequestBytes[41] = 0x00;
                            malformedRequestBytes[42] = 0x00;
                            malformedRequestBytes[43] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2IoctlRequest.ReadFrom(malformedRequestBytes),
                                "SMB2 IOCTL requests should reject non-zero output counts.");

                            byte[] malformedResponseBytes = new Smb2IoctlResponse
                            {
                                CtlCode = (uint)FsctlCode.QueryNetworkInterfaceInfo,
                                PersistentFileId = UInt64.MaxValue,
                                VolatileFileId = UInt64.MaxValue,
                                InputBuffer = Array.Empty<byte>(),
                                OutputBuffer = new byte[] { 0x01, 0x02 },
                                Flags = 0
                            }.ToByteArray();
                            malformedResponseBytes[32] = 0x71;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2IoctlResponse.ReadFrom(malformedResponseBytes),
                                "SMB2 IOCTL responses should reject unaligned output-buffer offsets.");

                            byte[] paddedResponse = Combine(
                                new Smb2IoctlResponse
                                {
                                    CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                                    PersistentFileId = 1,
                                    VolatileFileId = 2,
                                    InputBuffer = Array.Empty<byte>(),
                                    OutputBuffer = Array.Empty<byte>(),
                                    Flags = 0
                                }.ToByteArray(),
                                new byte[] { 0x7F });
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2CompoundPayloadHelper.TrimResponsePayload(Smb2Command.Ioctl, paddedResponse),
                                "Compounded IOCTL responses should reject non-zero trailing padding.");

                            byte[] malformedSnapshotArrayBytes = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 1,
                                Snapshots = new string[] { "@GMT-2025.01.02-03.04.05" }
                            }.ToByteArray();
                            malformedSnapshotArrayBytes[8] = 0x01;
                            malformedSnapshotArrayBytes[9] = 0x00;
                            malformedSnapshotArrayBytes[10] = 0x00;
                            malformedSnapshotArrayBytes[11] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvSnapshotArray.ReadFrom(malformedSnapshotArrayBytes),
                                "SRV_SNAPSHOT_ARRAY should reject payloads whose declared array length does not match the available bytes.");

                            byte[] invalidSnapshotTokenBytes = new SrvSnapshotArray
                            {
                                NumberOfSnapshots = 1,
                                Snapshots = new string[] { "@GMT-2025.01.02-03.04.05" }
                            }.ToByteArray();
                            invalidSnapshotTokenBytes[12] = 0x4E;
                            invalidSnapshotTokenBytes[13] = 0x00;
                            invalidSnapshotTokenBytes[14] = 0x4F;
                            invalidSnapshotTokenBytes[15] = 0x00;
                            invalidSnapshotTokenBytes[16] = 0x50;
                            invalidSnapshotTokenBytes[17] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvSnapshotArray.ReadFrom(invalidSnapshotTokenBytes),
                                "SRV_SNAPSHOT_ARRAY should reject tokens that do not use the expected @GMT format.");

                            byte[] invalidValidateRequestBytes = new ValidateNegotiateInfoRequest
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ClientGuid = Guid.Parse("D1B8A5FB-9F30-4BF4-84E9-33616D5F8265"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialects = new[] { SmbDialect.Smb2002 }
                            }.ToByteArray();
                            invalidValidateRequestBytes[22] = 0x00;
                            invalidValidateRequestBytes[23] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => ValidateNegotiateInfoRequest.ReadFrom(invalidValidateRequestBytes),
                                "VALIDATE_NEGOTIATE_INFO requests should reject a zero dialect count.");

                            byte[] invalidValidateResponseBytes = new ValidateNegotiateInfoResponse
                            {
                                Capabilities = Smb2GlobalCapabilities.None,
                                ServerGuid = Guid.Parse("6393D0FF-5149-40D7-9C67-7268E6AF47F7"),
                                SecurityMode = Smb2SecurityMode.SigningEnabled,
                                Dialect = SmbDialect.Smb2002
                            }.ToByteArray();
                            invalidValidateResponseBytes[22] = 0x99;
                            invalidValidateResponseBytes[23] = 0x99;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => ValidateNegotiateInfoResponse.ReadFrom(invalidValidateResponseBytes),
                                "VALIDATE_NEGOTIATE_INFO responses should reject unknown dialect values.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the bounded SRVSVC RPC suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor SrvsvcRpcSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.SrvsvcRpc",
                displayName: "SRVSVC RPC messages",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareEnumMessagesEncodeAndParseBoundedLevel1Shapes",
                        displayName: "SRVSVC share enumeration request and response encode bounded level 1 shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SrvsvcNetrShareEnumRequest request = new SrvsvcNetrShareEnumRequest
                            {
                                ServerName = string.Empty,
                                Level = 1,
                                PreferredMaximumLength = 0xFFFFFFFFU,
                                ResumeHandle = 9
                            };
                            byte[] requestBytes = request.ToByteArray();
                            LittleEndianReader requestReader = new LittleEndianReader(requestBytes);

                            TestAssertions.Equal((uint)0x00010000, requestReader.ReadUInt32(), "Expected the SRVSVC server-name pointer to remain non-null in the bounded request shape.");
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC server-name maximum count.");
                            TestAssertions.Equal((uint)0, requestReader.ReadUInt32(), "Unexpected SRVSVC server-name offset.");
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC server-name actual count.");
                            TestAssertions.Equal((ushort)0x0000, requestReader.ReadUInt16(), "Expected the bounded SRVSVC server-name string to be empty and null terminated.");
                            requestReader.Skip(2);
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC level value.");
                            TestAssertions.Equal((uint)1, requestReader.ReadUInt32(), "Unexpected SRVSVC union tag value.");
                            TestAssertions.Equal((uint)0x00020000, requestReader.ReadUInt32(), "Unexpected SRVSVC level-1 container pointer value.");
                            TestAssertions.Equal((uint)0, requestReader.ReadUInt32(), "Unexpected SRVSVC level-1 entries-read seed value.");
                            TestAssertions.Equal((uint)0, requestReader.ReadUInt32(), "Unexpected SRVSVC level-1 buffer pointer seed value.");
                            TestAssertions.Equal((uint)0xFFFFFFFFU, requestReader.ReadUInt32(), "Unexpected SRVSVC preferred maximum length.");
                            TestAssertions.Equal((uint)0x00030000, requestReader.ReadUInt32(), "Unexpected SRVSVC resume-handle pointer value.");
                            TestAssertions.Equal((uint)9, requestReader.ReadUInt32(), "Unexpected SRVSVC resume-handle seed value.");

                            LittleEndianWriter responseWriter = new LittleEndianWriter();
                            responseWriter.WriteUInt32(1);
                            responseWriter.WriteUInt32(1);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00020000);
                            responseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00030000);
                            responseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00040000);
                            responseWriter.WriteUInt32(0);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00050000);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00060000);
                            responseWriter.WriteUInt32(0x80000003U);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00070000);
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "share");
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "sample share");
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "IPC$");
                            DceRpcEncoding.WriteNdrUtf16String(responseWriter, "remote ipc");
                            responseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(responseWriter, 0x00080000);
                            responseWriter.WriteUInt32(4);
                            responseWriter.WriteUInt32(0);

                            SrvsvcNetrShareEnumResponse response = SrvsvcNetrShareEnumResponse.ReadFrom(responseWriter.ToArray());
                            TestAssertions.Equal((uint)1, response.Level, "Unexpected SRVSVC response level.");
                            TestAssertions.Equal((uint)2, response.TotalEntries, "Unexpected SRVSVC total entry count.");
                            TestAssertions.Equal((uint)4, response.ResumeHandle!.Value, "Unexpected SRVSVC resume handle value.");
                            TestAssertions.Equal((uint)0, response.ReturnCode, "Unexpected SRVSVC return code.");
                            TestAssertions.Equal(2, response.Shares.Length, "Unexpected SRVSVC share count.");
                            TestAssertions.Equal("share", response.Shares[0].Name, "Unexpected first SRVSVC share name.");
                            TestAssertions.Equal("sample share", response.Shares[0].Remark, "Unexpected first SRVSVC share remark.");
                            TestAssertions.Equal((uint)0, response.Shares[0].Type, "Unexpected first SRVSVC share type.");
                            TestAssertions.Equal("IPC$", response.Shares[1].Name, "Unexpected second SRVSVC share name.");
                            TestAssertions.Equal("remote ipc", response.Shares[1].Remark, "Unexpected second SRVSVC share remark.");
                            TestAssertions.Equal((uint)0x80000003U, response.Shares[1].Type, "Unexpected second SRVSVC share type.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareEnumReadersRejectMalformedInputs",
                        displayName: "SRVSVC share enumeration readers reject malformed request and response inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => new SrvsvcNetrShareEnumRequest
                                {
                                    Level = 2
                                }.ToByteArray(),
                                "The bounded SRVSVC request slice should reject unsupported levels.");

                            LittleEndianWriter invalidResponseWriter = new LittleEndianWriter();
                            invalidResponseWriter.WriteUInt32(1);
                            invalidResponseWriter.WriteUInt32(2);
                            DceRpcEncoding.WriteUniquePointer(invalidResponseWriter, 0);
                            invalidResponseWriter.WriteUInt32(0);
                            DceRpcEncoding.WriteUniquePointer(invalidResponseWriter, 0);
                            invalidResponseWriter.WriteUInt32(0);

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareEnumResponse.ReadFrom(invalidResponseWriter.ToArray()),
                                "The bounded SRVSVC response reader should reject mismatched union tags.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareEnumResponse.ReadFrom(new byte[7]),
                                "The bounded SRVSVC response reader should reject truncated payloads.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareGetInfoMessagesEncodeAndParseBoundedLevel2Shapes",
                        displayName: "SRVSVC share-info request and response encode bounded level 2 shapes",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SrvsvcNetrShareGetInfoRequest request = new SrvsvcNetrShareGetInfoRequest
                            {
                                ServerName = string.Empty,
                                ShareName = "public",
                                Level = 2
                            };
                            byte[] requestBytes = request.ToByteArray();
                            SrvsvcNetrShareGetInfoRequest parsedRequest = SrvsvcNetrShareGetInfoRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal(string.Empty, parsedRequest.ServerName, "Unexpected SRVSVC get-info server name.");
                            TestAssertions.Equal("public", parsedRequest.ShareName, "Unexpected SRVSVC get-info share name.");
                            TestAssertions.Equal((uint)2, parsedRequest.Level, "Unexpected SRVSVC get-info level.");

                            SrvsvcNetrShareGetInfoResponse successResponse = SrvsvcNetrShareGetInfoResponse.Create(
                                new SrvsvcShareInfo2
                                {
                                    Name = "public",
                                    Type = 0,
                                    Remark = "sample share",
                                    Permissions = 0,
                                    MaximumUses = UInt32.MaxValue,
                                    CurrentUses = 3,
                                    Path = @"C:\shares\public",
                                    Password = string.Empty
                                },
                                SrvsvcNetrShareGetInfoResponse.ErrorSuccess);
                            SrvsvcNetrShareGetInfoResponse parsedSuccessResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(successResponse.ToByteArray());
                            TestAssertions.Equal((uint)0, parsedSuccessResponse.ReturnCode, "Unexpected SRVSVC get-info success return code.");
                            TestAssertions.True(parsedSuccessResponse.Share != null, "Expected SRVSVC get-info success responses to carry share details.");
                            TestAssertions.Equal("public", parsedSuccessResponse.Share!.Name, "Unexpected SRVSVC get-info share name.");
                            TestAssertions.Equal("sample share", parsedSuccessResponse.Share.Remark, "Unexpected SRVSVC get-info share remark.");
                            TestAssertions.Equal((uint)3, parsedSuccessResponse.Share.CurrentUses, "Unexpected SRVSVC get-info current use count.");
                            TestAssertions.Equal(@"C:\shares\public", parsedSuccessResponse.Share.Path, "Unexpected SRVSVC get-info share path.");

                            SrvsvcNetrShareGetInfoResponse missingResponse = SrvsvcNetrShareGetInfoResponse.Create(
                                share: null,
                                returnCode: SrvsvcNetrShareGetInfoResponse.NerrNetNameNotFound);
                            SrvsvcNetrShareGetInfoResponse parsedMissingResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(missingResponse.ToByteArray());
                            TestAssertions.Equal(SrvsvcNetrShareGetInfoResponse.NerrNetNameNotFound, parsedMissingResponse.ReturnCode, "Unexpected SRVSVC get-info missing-share return code.");
                            TestAssertions.True(parsedMissingResponse.Share == null, "Expected SRVSVC get-info missing-share responses not to carry share details.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.SrvsvcRpc",
                        caseId: "SrvsvcShareGetInfoReadersRejectMalformedInputs",
                        displayName: "SRVSVC share-info readers reject malformed request and response inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ArgumentNullException>(
                                () => new SrvsvcNetrShareGetInfoRequest
                                {
                                    ShareName = string.Empty
                                }.ToByteArray(),
                                "The bounded SRVSVC get-info request slice should reject missing share names.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => new SrvsvcNetrShareGetInfoRequest
                                {
                                    ShareName = "public",
                                    Level = 1
                                }.ToByteArray(),
                                "The bounded SRVSVC get-info request slice should reject unsupported levels.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareGetInfoRequest.ReadFrom(new byte[7]),
                                "The bounded SRVSVC get-info request reader should reject truncated payloads.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareGetInfoResponse.ReadFrom(new byte[7]),
                                "The bounded SRVSVC get-info response reader should reject truncated payloads.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SrvsvcNetrShareGetInfoResponse.ReadFrom(new byte[]
                                {
                                    0x00, 0x00, 0x00, 0x00,
                                    0x00, 0x00, 0x00, 0x00
                                }),
                                "The bounded SRVSVC get-info response reader should reject success without share details.");

                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the bounded DFS referral codec suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor DfsReferralCodecSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.DfsReferral",
                displayName: "Bounded DFS referral codecs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.DfsReferral",
                        caseId: "DfsReferralRequestAndResponseRoundTripBoundedV2Entries",
                        displayName: "Bounded DFS referral request and response round-trip a representative v2 entry",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            DfsReferralRequest request = new DfsReferralRequest
                            {
                                MaxReferralLevel = 2,
                                RequestPath = @"\labserver\namespace\link"
                            };
                            byte[] requestBytes = request.ToByteArray();
                            DfsReferralRequest parsedRequest = DfsReferralRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal((ushort)2, parsedRequest.MaxReferralLevel, "Unexpected DFS referral request maximum level.");
                            TestAssertions.Equal(@"\labserver\namespace\link", parsedRequest.RequestPath, "Unexpected DFS referral request path.");

                            DfsReferralResponse response = new DfsReferralResponse
                            {
                                PathConsumed = (ushort)(@"\labserver\namespace".Length * 2),
                                HeaderFlags = DfsReferralHeaderFlags.StorageServers,
                                Entries = new[]
                                {
                                    new DfsReferralEntryV2
                                    {
                                        IsRootTarget = false,
                                        TimeToLive = 600,
                                        DfsPath = @"\labserver\namespace",
                                        NetworkAddress = @"\target\share"
                                    }
                                }
                            };
                            byte[] responseBytes = response.ToByteArray();
                            DfsReferralResponse parsedResponse = DfsReferralResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(response.PathConsumed, parsedResponse.PathConsumed, "Unexpected DFS referral response path-consumed value.");
                            TestAssertions.Equal(DfsReferralHeaderFlags.StorageServers, parsedResponse.HeaderFlags, "Unexpected DFS referral response header flags.");
                            TestAssertions.Equal(1, parsedResponse.Entries.Length, "Unexpected DFS referral entry count.");
                            TestAssertions.Equal(@"\labserver\namespace", parsedResponse.Entries[0].DfsPath, "Unexpected DFS referral entry DFS path.");
                            TestAssertions.Equal(@"\target\share", parsedResponse.Entries[0].NetworkAddress, "Unexpected DFS referral entry network address.");
                            TestAssertions.Equal((uint)600, parsedResponse.Entries[0].TimeToLive, "Unexpected DFS referral entry TTL.");
                            TestAssertions.False(parsedResponse.Entries[0].IsRootTarget, "Unexpected DFS referral root-target flag.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.DfsReferral",
                        caseId: "DfsReferralReadersRejectMalformedInputs",
                        displayName: "Bounded DFS referral readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralRequest.ReadFrom(new byte[] { 0x02, 0x00, 0x5C }),
                                "The DFS referral request reader should reject odd-length buffers.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralRequest.ReadFrom(new byte[] { 0x02, 0x00, 0x00, 0x00 }),
                                "The DFS referral request reader should reject empty paths.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => DfsReferralResponse.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "The DFS referral response reader should reject truncated headers.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the negotiate context suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor NegotiateContextSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Negotiate",
                displayName: "Negotiate context models",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "NegotiateContextModelsRoundTrip",
                        displayName: "Negotiate context models round-trip deterministic payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            PreauthIntegrityCapabilities preauth = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD }
                            };

                            byte[] preauthBytes = preauth.ToByteArray();
                            PreauthIntegrityCapabilities parsedPreauth = PreauthIntegrityCapabilities.ReadFrom(preauthBytes);
                            TestAssertions.Equal(1, parsedPreauth.HashAlgorithms.Length, "Unexpected preauth hash algorithm count.");
                            TestAssertions.Equal(HashAlgorithmId.Sha512, parsedPreauth.HashAlgorithms[0], "Unexpected preauth hash algorithm.");
                            TestAssertions.SequenceEqual(preauth.Salt, parsedPreauth.Salt, "Unexpected preauth salt bytes.");

                            SigningCapabilities signing = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.HmacSha256, SigningAlgorithmId.AesGmac }
                            };

                            byte[] signingBytes = signing.ToByteArray();
                            SigningCapabilities parsedSigning = SigningCapabilities.ReadFrom(signingBytes);
                            TestAssertions.Equal(2, parsedSigning.SigningAlgorithms.Length, "Unexpected signing algorithm count.");
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, parsedSigning.SigningAlgorithms[0], "Unexpected first signing algorithm.");
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, parsedSigning.SigningAlgorithms[1], "Unexpected second signing algorithm.");

                            Smb2NegotiateContextHeader header = new Smb2NegotiateContextHeader
                            {
                                ContextType = Smb2NegotiateContextType.SigningCapabilities,
                                DataLength = (ushort)signingBytes.Length,
                                Reserved = 7
                            };

                            Smb2NegotiateContextHeader parsedHeader = Smb2NegotiateContextHeader.ReadFrom(header.ToByteArray());
                            TestAssertions.Equal(Smb2NegotiateContextType.SigningCapabilities, parsedHeader.ContextType, "Unexpected negotiate context type.");
                            TestAssertions.Equal((ushort)signingBytes.Length, parsedHeader.DataLength, "Unexpected negotiate context payload length.");
                            TestAssertions.Equal(7U, parsedHeader.Reserved, "Unexpected negotiate context reserved field.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "EncryptionAndNetnameNegotiateContextsRoundTripDeterministicPayloads",
                        displayName: "Encryption and NETNAME negotiate context models round-trip deterministic payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            EncryptionCapabilities encryption = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            };
                            byte[] encryptionBytes = encryption.ToByteArray();
                            EncryptionCapabilities parsedEncryption = EncryptionCapabilities.ReadFrom(encryptionBytes);
                            TestAssertions.Equal(3, parsedEncryption.Ciphers.Length, "Unexpected encryption cipher count.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, parsedEncryption.Ciphers[0], "Unexpected first cipher.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, parsedEncryption.Ciphers[1], "Unexpected second cipher.");
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Ccm, parsedEncryption.Ciphers[2], "Unexpected third cipher.");

                            NetnameNegotiateContext netname = new NetnameNegotiateContext
                            {
                                ServerName = "files.example.test"
                            };
                            byte[] netnameBytes = netname.ToByteArray();
                            NetnameNegotiateContext parsedNetname = NetnameNegotiateContext.ReadFrom(netnameBytes);
                            TestAssertions.Equal("files.example.test", parsedNetname.ServerName, "Unexpected NETNAME server name.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "NegotiateContextReadersRejectMalformedInputs",
                        displayName: "Negotiate context readers reject malformed inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextHeader.ReadFrom(new byte[7]),
                                "A truncated negotiate context header should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => PreauthIntegrityCapabilities.ReadFrom(new byte[] { 0x00, 0x00, 0x00, 0x00 }),
                                "Preauth integrity capabilities without algorithms should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SigningCapabilities.ReadFrom(new byte[] { 0x00, 0x00, 0x00, 0x00 }),
                                "Signing capabilities without algorithms should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => EncryptionCapabilities.ReadFrom(new byte[] { 0x00, 0x00 }),
                                "Encryption capabilities without ciphers should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => EncryptionCapabilities.ReadFrom(new byte[] { 0x02, 0x00, 0x01, 0x00 }),
                                "Encryption capabilities truncated for the declared cipher count should fail to parse.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => NetnameNegotiateContext.ReadFrom(new byte[] { 0x00, 0x00, 0x00 }),
                                "NETNAME negotiate context with an odd-length payload should fail to parse.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextListEncodesAndDecodesAlignedTypedEntries",
                        displayName: "SMB 3.1.1 negotiate context list encodes and decodes 8-byte aligned typed entries",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x11, 0x22, 0x33 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray();
                            byte[] signingPayload = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac, SigningAlgorithmId.AesCmac, SigningAlgorithmId.HmacSha256 }
                            }.ToByteArray();

                            Smb2NegotiateContextEntry[] entries = new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload }
                            };

                            byte[] encoded = Smb2NegotiateContextList.Encode(entries);

                            int firstEntrySize = ((8 + preauthPayload.Length + 7) / 8) * 8;
                            int secondEntrySize = ((8 + encryptionPayload.Length + 7) / 8) * 8;
                            int thirdEntrySize = 8 + signingPayload.Length;
                            int expectedLength = firstEntrySize + secondEntrySize + thirdEntrySize;
                            TestAssertions.Equal(expectedLength, encoded.Length, "Encoded SMB 3.1.1 negotiate context list length should reflect 8-byte padding between entries and no required padding after the final entry.");

                            Smb2NegotiateContextEntry[] decoded = Smb2NegotiateContextList.Decode(encoded, entries.Length);
                            TestAssertions.Equal(3, decoded.Length, "Unexpected decoded negotiate context count.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decoded[0].ContextType, "Unexpected first decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decoded[1].ContextType, "Unexpected second decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.SigningCapabilities, decoded[2].ContextType, "Unexpected third decoded context type.");
                            TestAssertions.SequenceEqual(preauthPayload, decoded[0].Payload, "Unexpected preauth payload bytes.");
                            TestAssertions.SequenceEqual(encryptionPayload, decoded[1].Payload, "Unexpected encryption payload bytes.");
                            TestAssertions.SequenceEqual(signingPayload, decoded[2].Payload, "Unexpected signing payload bytes.");

                            PreauthIntegrityCapabilities parsedPreauth = PreauthIntegrityCapabilities.ReadFrom(decoded[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, parsedPreauth.HashAlgorithms[0], "Decoded preauth payload should round-trip through PreauthIntegrityCapabilities.ReadFrom.");
                            EncryptionCapabilities parsedEncryption = EncryptionCapabilities.ReadFrom(decoded[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, parsedEncryption.Ciphers[0], "Decoded encryption payload should round-trip through EncryptionCapabilities.ReadFrom.");
                            SigningCapabilities parsedSigning = SigningCapabilities.ReadFrom(decoded[2].Payload);
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, parsedSigning.SigningAlgorithms[0], "Decoded signing payload should round-trip through SigningCapabilities.ReadFrom.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateRequestRoundTripsTypedNegotiateContextEntries",
                        displayName: "SMB 3.1.1 negotiate request round-trips typed negotiate-context entries",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x42 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes128Gcm }
                            }.ToByteArray();

                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                ClientGuid = Guid.Parse("9F2A4D58-1F00-4D44-8E76-7F7B5F4F8B72"),
                                Dialects = new SmbDialect[] { SmbDialect.Smb2002, SmbDialect.Smb21, SmbDialect.Smb30, SmbDialect.Smb302, SmbDialect.Smb311 }
                            };
                            request.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload }
                            });

                            byte[] requestBytes = request.ToByteArray();
                            Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(requestBytes);
                            TestAssertions.Equal((ushort)2, parsedRequest.NegotiateContextCount, "Unexpected SMB 3.1.1 negotiate context count after round-trip.");
                            Smb2NegotiateContextEntry[] decodedEntries = parsedRequest.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(2, decodedEntries.Length, "Unexpected decoded negotiate-context entry count.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decodedEntries[0].ContextType, "Unexpected first decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decodedEntries[1].ContextType, "Unexpected second decoded context type.");
                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Decoded preauth hash algorithm should round-trip.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, decodedEncryption.Ciphers[0], "Decoded encryption cipher should round-trip.");

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateResponseRoundTripsTypedNegotiateContextEntries",
                        displayName: "SMB 3.1.1 negotiate response round-trips typed negotiate-context entries",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x55, 0x66, 0x77, 0x88 }
                            }.ToByteArray();
                            byte[] encryptionPayload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm }
                            }.ToByteArray();

                            Smb2NegotiateResponse response = new Smb2NegotiateResponse
                            {
                                Dialect = SmbDialect.Smb311,
                                ServerGuid = Guid.Parse("0F11D8A6-3344-4F2C-8FB0-1A6E6F7B9C50"),
                                Capabilities = Smb2GlobalCapabilities.Encryption,
                                MaxTransactSize = 1048576,
                                MaxReadSize = 1048576,
                                MaxWriteSize = 1048576,
                                SystemTime = 0x01D8112233445566UL,
                                ServerStartTime = 0x01D811223344AABBUL,
                                SecurityBuffer = new byte[] { 0xA0, 0x60, 0x82, 0x01, 0x00, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02 }
                            };
                            response.SetNegotiateContextEntries(new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.EncryptionCapabilities, Payload = encryptionPayload }
                            });

                            byte[] responseBytes = response.ToByteArray();
                            Smb2NegotiateResponse parsedResponse = Smb2NegotiateResponse.ReadFrom(responseBytes);
                            TestAssertions.Equal(SmbDialect.Smb311, parsedResponse.Dialect, "Unexpected SMB 3.1.1 negotiate response dialect after round-trip.");
                            TestAssertions.Equal((ushort)2, parsedResponse.NegotiateContextCount, "Unexpected SMB 3.1.1 negotiate context count after round-trip.");
                            TestAssertions.SequenceEqual(response.SecurityBuffer, parsedResponse.SecurityBuffer, "SecurityBuffer should round-trip on the SMB 3.1.1 negotiate response.");

                            Smb2NegotiateContextEntry[] decodedEntries = parsedResponse.DecodeNegotiateContextEntries();
                            TestAssertions.Equal(2, decodedEntries.Length, "Unexpected decoded negotiate-context entry count.");
                            TestAssertions.Equal(Smb2NegotiateContextType.PreauthIntegrityCapabilities, decodedEntries[0].ContextType, "Unexpected first decoded context type.");
                            TestAssertions.Equal(Smb2NegotiateContextType.EncryptionCapabilities, decodedEntries[1].ContextType, "Unexpected second decoded context type.");
                            PreauthIntegrityCapabilities decodedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedEntries[0].Payload);
                            TestAssertions.Equal(HashAlgorithmId.Sha512, decodedPreauth.HashAlgorithms[0], "Decoded preauth hash algorithm should round-trip on the response.");
                            EncryptionCapabilities decodedEncryption = EncryptionCapabilities.ReadFrom(decodedEntries[1].Payload);
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes256Gcm, decodedEncryption.Ciphers[0], "Decoded encryption cipher should round-trip on the response.");

                            Smb2NegotiateResponse smb302Response = new Smb2NegotiateResponse
                            {
                                Dialect = SmbDialect.Smb302,
                                SecurityBuffer = new byte[] { 0x01, 0x02, 0x03 }
                            };
                            byte[] smb302ResponseBytes = smb302Response.ToByteArray();
                            Smb2NegotiateResponse parsedSmb302Response = Smb2NegotiateResponse.ReadFrom(smb302ResponseBytes);
                            TestAssertions.Equal((ushort)0, parsedSmb302Response.NegotiateContextCount, "SMB 3.0.2 negotiate responses should not carry SMB 3.1.1 negotiate-context counts.");
                            TestAssertions.Equal(0, parsedSmb302Response.NegotiateContextData.Length, "SMB 3.0.2 negotiate responses should not carry SMB 3.1.1 negotiate-context bytes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextListRejectsTruncatedAndOversizedInputs",
                        displayName: "SMB 3.1.1 negotiate context list rejects truncated headers and payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextList.Decode(new byte[] { 0x01, 0x00, 0x04, 0x00, 0x00, 0x00 }, 1),
                                "Truncated context-header buffers should fail to decode.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextList.Decode(new byte[] { 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAA }, 1),
                                "Context payloads truncated below the declared length should fail to decode.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextSelectorPicksSupportedAlgorithmsAndRejectsUnsupportedClientOffers",
                        displayName: "SMB 3.1.1 negotiate-context selector picks supported algorithms and rejects unsupported client offers",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            HashAlgorithmId selectedHash = Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(
                                new PreauthIntegrityCapabilities
                                {
                                    HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                    Salt = new byte[] { 0xAA }
                                });
                            TestAssertions.Equal(HashAlgorithmId.Sha512, selectedHash, "Selector should pick SHA-512 when offered.");
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(new PreauthIntegrityCapabilities
                                {
                                    HashAlgorithms = new HashAlgorithmId[] { (HashAlgorithmId)0x9999 },
                                    Salt = Array.Empty<byte>()
                                }),
                                "Selector should reject SMB 3.1.1 client preauth offers without a supported hash algorithm.");
                            TestAssertions.Throws<ArgumentNullException>(
                                () => Smb311NegotiateContextSelector.SelectPreauthHashAlgorithm(null!),
                                "Selector should reject null preauth-capability inputs.");

                            SigningAlgorithmId defaultSigning = Smb311NegotiateContextSelector.SelectSigningAlgorithm(null);
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, defaultSigning, "Selector should default to HMAC-SHA256 when no signing context is present.");

                            SigningAlgorithmId gmacFromMixed = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac, SigningAlgorithmId.AesCmac, SigningAlgorithmId.HmacSha256 }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, gmacFromMixed, "Selector should prefer AES-GMAC over AES-CMAC and HMAC-SHA256 when offered.");

                            SigningAlgorithmId aesCmacFromCmacAndHmac = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesCmac, SigningAlgorithmId.HmacSha256 }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.AesCmac, aesCmacFromCmacAndHmac, "Selector should fall back to AES-CMAC when AES-GMAC is not offered.");

                            SigningAlgorithmId gmacOnlyAccepted = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, gmacOnlyAccepted, "Selector should accept SMB 3.1.1 signing offers that contain only AES-GMAC now that per-message GMAC signing is wired.");

                            SigningAlgorithmId hmacFromHmacOnly = Smb311NegotiateContextSelector.SelectSigningAlgorithm(new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.HmacSha256 }
                            });
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, hmacFromHmacOnly, "Selector should fall back to HMAC-SHA256 when neither AES-GMAC nor AES-CMAC is offered.");

                            SmbCipherAlgorithmId? noCipherSelected = Smb311NegotiateContextSelector.SelectCipher(null);
                            TestAssertions.True(noCipherSelected == null, "Selector should return null when no encryption context is offered.");

                            SmbCipherAlgorithmId? gcmPreferredSelected = Smb311NegotiateContextSelector.SelectCipher(new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm, SmbCipherAlgorithmId.Aes128Gcm, SmbCipherAlgorithmId.Aes128Ccm }
                            });
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Gcm, gcmPreferredSelected!.Value, "Selector should prefer AES-128-GCM over AES-128-CCM when both are offered.");

                            SmbCipherAlgorithmId? aes128CcmFallback = Smb311NegotiateContextSelector.SelectCipher(new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm, SmbCipherAlgorithmId.Aes128Ccm }
                            });
                            TestAssertions.Equal(SmbCipherAlgorithmId.Aes128Ccm, aes128CcmFallback!.Value, "Selector should fall back to AES-128-CCM when AES-128-GCM is not offered.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb311NegotiateContextSelector.SelectCipher(new EncryptionCapabilities
                                {
                                    Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes256Gcm }
                                }),
                                "Selector should reject encryption offers without AES-128-GCM or AES-128-CCM until AES-256 ciphers are wired.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Negotiate",
                        caseId: "Smb311NegotiateContextListRejectsTamperedCountAndPayloads",
                        displayName: "SMB 3.1.1 negotiate context list rejects tampered context counts and tampered payloads",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] preauthPayload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0xAA, 0xBB }
                            }.ToByteArray();
                            byte[] signingPayload = new SigningCapabilities
                            {
                                SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.AesGmac }
                            }.ToByteArray();

                            Smb2NegotiateContextEntry[] entries = new[]
                            {
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities, Payload = preauthPayload },
                                new Smb2NegotiateContextEntry { ContextType = Smb2NegotiateContextType.SigningCapabilities, Payload = signingPayload }
                            };

                            byte[] encoded = Smb2NegotiateContextList.Encode(entries);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateContextList.Decode(encoded, entries.Length + 1),
                                "Decoding with an inflated entry count beyond the carried payload should be rejected.");

                            byte[] tamperedHashCount = (byte[])encoded.Clone();
                            tamperedHashCount[8] = 0x00;
                            tamperedHashCount[9] = 0x00;
                            Smb2NegotiateContextEntry[] decodedAfterTamper = Smb2NegotiateContextList.Decode(tamperedHashCount, entries.Length);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => PreauthIntegrityCapabilities.ReadFrom(decodedAfterTamper[0].Payload),
                                "A preauth context with a zeroed hash-algorithm count should be rejected by the typed reader after decode.");

                            byte[] tamperedHashAlgorithm = (byte[])encoded.Clone();
                            tamperedHashAlgorithm[12] = 0xFF;
                            tamperedHashAlgorithm[13] = 0xFF;
                            Smb2NegotiateContextEntry[] decodedTamperedAlgorithm = Smb2NegotiateContextList.Decode(tamperedHashAlgorithm, entries.Length);
                            PreauthIntegrityCapabilities tamperedPreauth = PreauthIntegrityCapabilities.ReadFrom(decodedTamperedAlgorithm[0].Payload);
                            TestAssertions.True(
                                tamperedPreauth.HashAlgorithms[0] != HashAlgorithmId.Sha512,
                                "A bytewise-tampered preauth payload should not match the original hash-algorithm identifier.");

                            Smb2NegotiateRequest request = new Smb2NegotiateRequest
                            {
                                Dialects = new SmbDialect[] { SmbDialect.Smb311 }
                            };
                            request.SetNegotiateContextEntries(entries);
                            byte[] requestBytes = request.ToByteArray();
                            byte[] tamperedRequestBytes = (byte[])requestBytes.Clone();
                            int contextOffsetField = 28;
                            tamperedRequestBytes[contextOffsetField] = 0x00;
                            tamperedRequestBytes[contextOffsetField + 1] = 0x00;
                            tamperedRequestBytes[contextOffsetField + 2] = 0x00;
                            tamperedRequestBytes[contextOffsetField + 3] = 0x00;
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb2NegotiateRequest.ReadFrom(tamperedRequestBytes),
                                "Tampering an SMB 3.1.1 negotiate request to point its negotiate-context offset below the fixed header should be rejected.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the FSCC catalog suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor FsccCatalogSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.FSCC",
                displayName: "FSCC information class catalogs",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.FSCC",
                        caseId: "KnownInformationClassesResolve",
                        displayName: "Known FSCC information classes resolve and unknown values miss",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            bool foundFileInfo = FsccInformationClassCatalog.TryGetFileInformationClassInfo(FileInformationClass.BasicInformation, out FsccInformationClassInfo? fileInfo);
                            TestAssertions.True(foundFileInfo, "Expected BasicInformation metadata to be present.");
                            TestAssertions.True(fileInfo != null, "Expected BasicInformation metadata to be non-null.");
                            TestAssertions.Equal("BasicInformation", fileInfo!.Name, "Unexpected BasicInformation metadata name.");
                            TestAssertions.True(fileInfo.RequiresFileHandle, "BasicInformation should require a file handle.");

                            bool foundFileSystemInfo = FsccInformationClassCatalog.TryGetFileSystemInformationClassInfo(FileSystemInformationClass.VolumeInformation, out FsccInformationClassInfo? fileSystemInfo);
                            TestAssertions.True(foundFileSystemInfo, "Expected VolumeInformation metadata to be present.");
                            TestAssertions.True(fileSystemInfo != null, "Expected VolumeInformation metadata to be non-null.");
                            TestAssertions.Equal("VolumeInformation", fileSystemInfo!.Name, "Unexpected VolumeInformation metadata name.");
                            TestAssertions.False(fileSystemInfo.RequiresFileHandle, "VolumeInformation should not require a file handle.");

                            bool foundUnknownFileInfo = FsccInformationClassCatalog.TryGetFileInformationClassInfo(unchecked((FileInformationClass)0xFFFF), out FsccInformationClassInfo? missingFileInfo);
                            TestAssertions.False(foundUnknownFileInfo, "Unexpected metadata was returned for an unknown file information class.");
                            TestAssertions.True(missingFileInfo == null, "Unknown file information classes should not return metadata.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.FSCC",
                        caseId: "UnknownInformationClassesRejectResolution",
                        displayName: "Unknown FSCC information classes reject resolution",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            bool foundUnknownFileInfo = FsccInformationClassCatalog.TryGetFileInformationClassInfo(unchecked((FileInformationClass)0x7FFF), out FsccInformationClassInfo? missingFileInfo);
                            TestAssertions.False(foundUnknownFileInfo, "Unexpected file-information metadata was returned for an unknown FSCC information class.");
                            TestAssertions.True(missingFileInfo == null, "Unknown file-information classes should not return metadata.");

                            bool foundUnknownFileSystemInfo = FsccInformationClassCatalog.TryGetFileSystemInformationClassInfo(unchecked((FileSystemInformationClass)0x7FFF), out FsccInformationClassInfo? missingFileSystemInfo);
                            TestAssertions.False(foundUnknownFileSystemInfo, "Unexpected filesystem metadata was returned for an unknown FSCC information class.");
                            TestAssertions.True(missingFileSystemInfo == null, "Unknown filesystem information classes should not return metadata.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the state lifecycle suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor StateLifecycleSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.State",
                displayName: "Protocol state lifecycles",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "ConnectionAndCreditStatesFollowLifecycle",
                        displayName: "Connection and credit states follow lifecycle rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            ConnectionState connection = new ConnectionState();
                            TestAssertions.False(connection.IsNegotiated, "A new connection should not be negotiated.");

                            connection.Credits.Grant(5);
                            connection.Credits.Consume(2);
                            connection.Credits.Return(1);
                            TestAssertions.Equal(4, connection.Credits.AvailableCredits, "Unexpected credit count.");

                            connection.Negotiate(SmbDialect.Smb311);
                            TestAssertions.True(connection.IsNegotiated, "The connection should be marked negotiated.");
                            TestAssertions.Equal(SmbDialect.Smb311, connection.NegotiatedDialect!.Value, "Unexpected negotiated dialect.");

                            connection.Dispose();
                            TestAssertions.True(connection.IsDisposed, "The connection should report that it has been disposed.");
                            TestAssertions.True(connection.Credits.IsDisposed, "Disposing the connection should dispose the credit state.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => connection.Negotiate(SmbDialect.Smb30),
                                "Using a disposed connection should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "SessionTreeAndOpenStatesFollowLifecycle",
                        displayName: "Session, tree, and open states follow lifecycle rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SessionState session = new SessionState();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => session.Authenticate(),
                                "Authenticating before binding a session identifier should fail.");
                            session.Bind(0x0102030405060708UL);
                            session.Authenticate();
                            TestAssertions.True(session.IsAuthenticated, "The session should be authenticated.");

                            TreeConnectState tree = new TreeConnectState();
                            tree.Connect(0xABCD1234U, "share");
                            TestAssertions.True(tree.IsConnected, "The tree should be connected.");
                            TestAssertions.Equal("share", tree.ShareName, "Unexpected share name.");
                            tree.Disconnect();
                            TestAssertions.False(tree.IsConnected, "The tree should be disconnected.");

                            OpenState open = new OpenState();
                            TestAssertions.Throws<ArgumentException>(
                                () => open.Bind(0, 0, "file.txt"),
                                "Binding an open with zero file identifiers should fail.");
                            open.Bind(1, 2, "folder\\file.txt");
                            open.MarkDeletePending();
                            TestAssertions.True(open.IsDeletePending, "The open should be delete-pending.");
                            TestAssertions.Equal("folder\\file.txt", open.Path, "Unexpected open path.");

                            session.Dispose();
                            tree.Dispose();
                            open.Dispose();

                            TestAssertions.Throws<ObjectDisposedException>(
                                () => session.Bind(1),
                                "Using a disposed session should fail.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => tree.Connect(1, "share"),
                                "Using a disposed tree should fail.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => open.MarkDeletePending(),
                                "Using a disposed open should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "RequestAndCompoundStatesFollowLifecycle",
                        displayName: "Request and compound states follow lifecycle rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            RequestState request = new RequestState();
                            request.Bind(42, Smb2Command.Read);
                            request.Complete();
                            TestAssertions.Equal(42UL, request.MessageId, "Unexpected request message identifier.");
                            TestAssertions.Equal(Smb2Command.Read, request.Command, "Unexpected request command.");
                            TestAssertions.True(request.IsCompleted, "The request should be completed.");

                            CompoundChainState compound = new CompoundChainState();
                            compound.Append(Smb2Command.Create);
                            compound.Append(Smb2Command.Close);
                            compound.Seal();
                            TestAssertions.Equal(2, compound.Commands.Count, "Unexpected compound command count.");
                            TestAssertions.Equal(Smb2Command.Create, compound.Commands[0], "Unexpected first compound command.");
                            TestAssertions.Equal(Smb2Command.Close, compound.Commands[1], "Unexpected second compound command.");
                            TestAssertions.True(compound.IsSealed, "The compound chain should be sealed.");
                            TestAssertions.Throws<InvalidOperationException>(
                                () => compound.Append(Smb2Command.Read),
                                "Appending to a sealed compound chain should fail.");

                            request.Dispose();
                            compound.Dispose();
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => request.Complete(),
                                "Using a disposed request should fail.");
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => compound.Seal(),
                                "Using a disposed compound chain should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.State",
                        caseId: "StateObjectsRejectInvalidTransitionsAndDisposedReuse",
                        displayName: "State objects reject invalid transitions and disposed reuse",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            CreditState credits = new CreditState();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => credits.Consume(1),
                                "Credit state should reject consuming credits before any have been granted.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => credits.Grant(0),
                                "Credit state should reject non-positive grants.");

                            SessionState session = new SessionState();
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => session.Bind(0),
                                "Session state should reject zero-valued session identifiers.");

                            CompoundChainState compound = new CompoundChainState();
                            compound.Seal();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => compound.Append(Smb2Command.Read),
                                "Compound state should reject appends after the chain is sealed.");

                            RequestState request = new RequestState();
                            request.Dispose();
                            TestAssertions.Throws<ObjectDisposedException>(
                                () => request.MarkAsync(1),
                                "Disposed request state should reject async assignment.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the bounded deterministic parser-mutation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor ParserMutationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Mutation",
                displayName: "Deterministic parser mutation smoke",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Mutation",
                        caseId: "BaselineProtocolCorpusParsesBeforeMutation",
                        displayName: "Baseline protocol corpus parses before mutation",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            foreach ((string _, byte[] baseline, Action<byte[]> parser) in BuildProtocolMutationCorpus())
                            {
                                parser(baseline);
                            }

                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Mutation",
                        caseId: "DeterministicProtocolMutationsRejectOrContainMalformedInputs",
                        displayName: "Deterministic protocol mutations reject or contain malformed inputs without unexpected parser failures",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            int totalMutations = 0;
                            int totalAccepted = 0;
                            int totalRejected = 0;

                            foreach ((string name, byte[] baseline, Action<byte[]> parser) in BuildProtocolMutationCorpus())
                            {
                                IReadOnlyList<byte[]> mutations = MutationTestUtilities.CreateDeterministicMutationCorpus(
                                    baseline,
                                    randomSeed: 0x43494653 ^ DeterministicTestHash.ComputeInt32(name),
                                    randomCount: 48);
                                MutationOutcomeSummary summary = MutationTestUtilities.ExecuteMutationCorpus(
                                    name,
                                    mutations,
                                    parser,
                                    MutationTestUtilities.IsExpectedMalformedInputException);

                                TestAssertions.True(summary.RejectedCount > 0, "Expected mutation corpus '" + name + "' to reject at least one malformed payload.");
                                totalMutations += summary.TotalCount;
                                totalAccepted += summary.AcceptedCount;
                                totalRejected += summary.RejectedCount;
                            }

                            TestAssertions.True(totalMutations >= 300, "Expected the deterministic parser-mutation corpus to execute at least 300 mutated payloads.");
                            TestAssertions.True(totalRejected >= 100, "Expected the deterministic parser-mutation corpus to reject a meaningful number of malformed payloads.");
                            TestAssertions.True(totalAccepted > 0, "Expected at least one deterministic mutation to remain structurally parseable.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Mutation",
                        caseId: "ReplayAttemptHelpersBuildAndPreserveSignedRequestBytesAndRejectInvalidInputs",
                        displayName: "Replay-attempt helpers build and preserve signed-request bytes and reject invalid inputs",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] capturedSignedRequest = new byte[]
                            {
                                0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x01, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
                                0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00,
                                0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                                0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                                0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
                            };

                            byte[] firstReplay = ReplayAttemptUtilities.CreateReplayCopy(capturedSignedRequest);
                            byte[] secondReplay = ReplayAttemptUtilities.CreateReplayCopy(capturedSignedRequest);
                            TestAssertions.SequenceEqual(capturedSignedRequest, firstReplay, "Replay copies should preserve the captured signed-request bytes.");
                            TestAssertions.SequenceEqual(firstReplay, secondReplay, "Repeated replay copies should be deterministic.");

                            firstReplay[0] = 0x00;
                            TestAssertions.True(capturedSignedRequest[0] == 0xFE, "Mutating a replay copy should not affect the captured signed-request bytes.");

                            IReadOnlyList<byte[]> replayBurst = ReplayAttemptUtilities.CreateReplayBurst(capturedSignedRequest, replayCount: 4);
                            TestAssertions.Equal(4, replayBurst.Count, "Unexpected replay-burst count.");

                            for (int index = 0; index < replayBurst.Count; index++)
                            {
                                TestAssertions.SequenceEqual(capturedSignedRequest, replayBurst[index], "Each replay-burst entry should match the captured signed request.");
                            }

                            TestAssertions.Throws<ArgumentNullException>(
                                () => ReplayAttemptUtilities.CreateReplayCopy(null!),
                                "Replay-copy helpers should reject null input.");
                            TestAssertions.Throws<ArgumentOutOfRangeException>(
                                () => ReplayAttemptUtilities.CreateReplayBurst(capturedSignedRequest, replayCount: 0),
                                "Replay-burst helpers should reject non-positive counts.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the security foundation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor SecurityFoundationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Security",
                displayName: "Security foundation primitives",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "PreauthHashAccumulatorMatchesTranscriptHash",
                        displayName: "Preauth hash accumulator matches the expected transcript hash",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] message1 = new byte[] { 0x01, 0x02, 0x03 };
                            byte[] message2 = new byte[] { 0x10, 0x20, 0x30, 0x40 };
                            PreauthIntegrityHashAccumulator accumulator = new PreauthIntegrityHashAccumulator();

                            accumulator.Append(message1);
                            byte[] expectedAfterMessage1 = SHA512.HashData(Combine(new byte[64], message1));
                            TestAssertions.SequenceEqual(expectedAfterMessage1, accumulator.CurrentHash, "Unexpected preauth transcript hash after the first message.");

                            accumulator.Append(message2);
                            byte[] expectedAfterMessage2 = SHA512.HashData(Combine(expectedAfterMessage1, message2));
                            TestAssertions.SequenceEqual(expectedAfterMessage2, accumulator.CurrentHash, "Unexpected preauth transcript hash after the second message.");

                            accumulator.Reset();
                            TestAssertions.SequenceEqual(new byte[64], accumulator.CurrentHash, "Reset should restore the zero transcript hash.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "PreauthHashAccumulatorRejectsUnsupportedAlgorithms",
                        displayName: "Preauth hash accumulator rejects unsupported algorithms",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.Throws<NotSupportedException>(
                                () => new PreauthIntegrityHashAccumulator((HashAlgorithmId)0xFFFF),
                                "Unsupported preauth algorithms should fail.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SigningAndKeyDerivationContractsRemainInterfaces",
                        displayName: "Signing and key-derivation contracts remain stable and discoverable",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Type messageSignerType = typeof(IMessageSigner);
                            Type keyDerivationProviderType = typeof(IKeyDerivationProvider);

                            TestAssertions.True(messageSignerType.IsInterface, "IMessageSigner must remain an interface.");
                            TestAssertions.True(keyDerivationProviderType.IsInterface, "IKeyDerivationProvider must remain an interface.");
                            TestAssertions.True(messageSignerType.GetProperty("AlgorithmId") != null, "IMessageSigner must expose AlgorithmId.");
                            TestAssertions.True(messageSignerType.GetProperty("SignatureLength") != null, "IMessageSigner must expose SignatureLength.");
                            TestAssertions.True(messageSignerType.GetProperty("RequiresNonce") != null, "IMessageSigner must expose RequiresNonce.");
                            TestAssertions.True(messageSignerType.GetMethod("Sign") != null, "IMessageSigner must expose Sign.");
                            TestAssertions.True(messageSignerType.GetMethod("Verify") != null, "IMessageSigner must expose Verify.");
                            TestAssertions.True(keyDerivationProviderType.GetMethod("DeriveKey") != null, "IKeyDerivationProvider must expose DeriveKey.");
                            TestAssertions.True(typeof(MessageSignerFactory).GetMethod("Create") != null, "MessageSignerFactory must expose Create.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "Smb3TransformPacketsRoundTripWithAes128Ccm",
                        displayName: "SMB3 transform packets round-trip with AES-128-CCM and preserve the declared session identifier",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] key = Hex("00112233445566778899AABBCCDDEEFF");
                            byte[] plaintextPacket = Hex("FE534D424000000000000000030000000100000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000400000000000000");
                            byte[] encryptedPacket = Smb3MessageTransform.EncryptPacket(plaintextPacket, 0x0102030405060708UL, key);
                            Smb2TransformHeader header = Smb2TransformHeader.ReadFrom(encryptedPacket);

                            TestAssertions.True(Smb2TransformHeader.LooksLikeTransformHeader(encryptedPacket), "Expected the encrypted SMB3 packet to begin with a transform header.");
                            TestAssertions.Equal(0x0102030405060708UL, header.SessionId, "Expected the SMB3 transform header to preserve the supplied session identifier.");
                            TestAssertions.Equal((uint)plaintextPacket.Length, header.OriginalMessageSize, "Expected the SMB3 transform header to preserve the plaintext packet length.");
                            TestAssertions.Equal((ushort)0x0001, header.Flags, "Expected the bounded SMB3 transform header to preserve the fixed transform-flag value.");
                            TestAssertions.SequenceEqual(
                                plaintextPacket,
                                Smb3MessageTransform.DecryptPacket(encryptedPacket, key, expectedSessionId: 0x0102030405060708UL),
                                "Expected the SMB3 transform packet to decrypt back to the original plaintext bytes.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "Smb3TransformPacketsRejectTamperingAndMalformedLengths",
                        displayName: "SMB3 transform packets reject tampering and malformed declared lengths",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] key = Hex("00112233445566778899AABBCCDDEEFF");
                            byte[] plaintextPacket = Hex("FE534D424000000000000000030000000100000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000400000000000000");
                            byte[] encryptedPacket = Smb3MessageTransform.EncryptPacket(plaintextPacket, 0x0102030405060708UL, key);

                            byte[] tamperedPacket = (byte[])encryptedPacket.Clone();
                            tamperedPacket[tamperedPacket.Length - 1] ^= 0x01;
                            TestAssertions.Throws<ProtocolValidationException>(
                                () => Smb3MessageTransform.DecryptPacket(tamperedPacket, key, expectedSessionId: 0x0102030405060708UL),
                                "Expected SMB3 transform packet tampering to fail authentication-tag validation.");

                            byte[] malformedLengthPacket = (byte[])encryptedPacket.Clone();
                            LittleEndianWriter writer = new LittleEndianWriter();
                            writer.WriteUInt32(checked((uint)plaintextPacket.Length + 1));
                            byte[] invalidLengthBytes = writer.ToArray();
                            Buffer.BlockCopy(invalidLengthBytes, 0, malformedLengthPacket, 36, 4);
                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => Smb3MessageTransform.DecryptPacket(malformedLengthPacket, key, expectedSessionId: 0x0102030405060708UL),
                                "Expected malformed SMB3 transform packet lengths to be rejected before decryption.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "Md4AndHmacMd5MatchKnownVectors",
                        displayName: "MD4 and HMAC-MD5 match known-answer vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.md4.empty"),
                                Md4.HashData(Array.Empty<byte>()),
                                "The MD4 digest for the empty string changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.md4.abc"),
                                Md4.HashData(Encoding.ASCII.GetBytes("abc")),
                                "The MD4 digest for 'abc' changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.hmac-md5.hi-there"),
                                HmacMd5.HashData(CreateRepeatedByteArray(0x0B, 16), Encoding.ASCII.GetBytes("Hi There")),
                                "The HMAC-MD5 known-answer vector changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "NtlmV2ResponsesAndMicMatchMicrosoftVectors",
                        displayName: "NTLMv2 challenge responses and MIC generation match Microsoft vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] expectedResponseKey = GoldenVectorStore.GetBytes("core.security.ntlm.response-key");
                            NtlmV2ClientChallenge clientChallenge = CreateMicrosoftNtlmV2ClientChallenge();
                            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                clientChallenge: clientChallenge);

                            TestAssertions.SequenceEqual(expectedResponseKey, responseSet.ResponseKeyNt, "The NTLMv2 response key changed.");
                            TestAssertions.SequenceEqual(expectedResponseKey, responseSet.ResponseKeyLm, "The LMv2 response key changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.ntlm.nt-challenge-response"),
                                responseSet.NtChallengeResponse.ToByteArray(),
                                "The NTLMv2 NT challenge response changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.ntlm.lm-challenge-response"),
                                responseSet.LmChallengeResponse,
                                "The LMv2 challenge response changed.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.ntlm.session-base-key"),
                                responseSet.SessionBaseKey,
                                "The NTLMv2 session-base key changed.");

                            bool verified = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: responseSet.LmChallengeResponse,
                                verifiedResponseSet: out NtlmV2ChallengeResponseSet? verifiedResponseSet);
                            TestAssertions.True(verified, "The Microsoft NTLMv2 example should verify successfully.");
                            TestAssertions.True(verifiedResponseSet != null, "Verification should return a response set.");
                            TestAssertions.SequenceEqual(responseSet.SessionBaseKey, verifiedResponseSet!.SessionBaseKey, "Verification changed the session-base key.");

                            bool verifiedWithOmittedLm = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: Array.Empty<byte>(),
                                verifiedResponseSet: out _);
                            TestAssertions.True(verifiedWithOmittedLm, "NTLMv2 verification should accept an omitted LM response when the NT response is valid.");

                            bool verifiedWithZeroLm = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: new byte[24],
                                verifiedResponseSet: out _);
                            TestAssertions.True(verifiedWithZeroLm, "NTLMv2 verification should accept a zeroed LM response when the NT response is valid.");

                            byte[] expectedMic = GoldenVectorStore.GetBytes("core.security.ntlm.mic");
                            byte[] mic = NtlmMessageIntegrityCode.Compute(
                                exportedSessionKey: CreateRepeatedByteArray(0x55, 16),
                                negotiateMessage: new byte[] { 0x01, 0x02, 0x03 },
                                challengeMessage: new byte[] { 0x04, 0x05 },
                                authenticateMessageWithZeroMic: new byte[] { 0x06, 0x07, 0x08 });
                            TestAssertions.SequenceEqual(expectedMic, mic, "The NTLM MIC known-answer vector changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SpnegoTokensRoundTripAndNegotiateMechanisms",
                        displayName: "SPNEGO tokens round-trip and negotiate a mutual mechanism",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SpnegoNegTokenInit initToken = new SpnegoNegTokenInit
                            {
                                MechanismTypes = new string[] { SpnegoMechanismOid.Kerberos, SpnegoMechanismOid.Ntlm },
                                RequestFlags = 0xA0000000U,
                                MechanismToken = Hex("01020304"),
                                MechanismListMic = Hex("AABBCCDD")
                            };

                            byte[] encodedInitToken = SpnegoTokenCodec.EncodeNegTokenInit(initToken);
                            TestAssertions.Equal((byte)0x60, encodedInitToken[0], "SPNEGO initial tokens should carry the GSS-API application wrapper.");

                            SpnegoNegTokenInit decodedInitToken = SpnegoTokenCodec.DecodeNegTokenInit(encodedInitToken);
                            TestAssertions.Equal(2, decodedInitToken.MechanismTypes.Length, "Unexpected SPNEGO mechanism count.");
                            TestAssertions.Equal(SpnegoMechanismOid.Kerberos, decodedInitToken.MechanismTypes[0], "Unexpected first SPNEGO mechanism OID.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, decodedInitToken.MechanismTypes[1], "Unexpected second SPNEGO mechanism OID.");
                            TestAssertions.Equal(0xA0000000U, decodedInitToken.RequestFlags!.Value, "Unexpected SPNEGO request flags.");
                            TestAssertions.SequenceEqual(Hex("01020304"), decodedInitToken.MechanismToken!, "Unexpected SPNEGO optimistic token bytes.");
                            TestAssertions.SequenceEqual(Hex("AABBCCDD"), decodedInitToken.MechanismListMic!, "Unexpected SPNEGO MIC bytes.");

                            bool selected = SpnegoMechanismNegotiator.TrySelectMechanism(
                                request: decodedInitToken,
                                supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                                selectedMechanism: out string? selectedMechanism);
                            TestAssertions.True(selected, "The NTLM mechanism should be selected from the offered list.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, selectedMechanism, "The selected SPNEGO mechanism changed.");

                            SpnegoNegTokenResp responseToken = SpnegoMechanismNegotiator.CreateNegotiationResponse(
                                request: decodedInitToken,
                                supportedMechanisms: new string[] { SpnegoMechanismOid.Ntlm },
                                mechanismResponseToken: Hex("05060708"),
                                completed: false);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, responseToken.NegotiationState!.Value, "Unexpected SPNEGO negotiation state.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, responseToken.SupportedMechanism, "Unexpected SPNEGO selected mechanism.");
                            TestAssertions.SequenceEqual(Hex("05060708"), responseToken.ResponseToken!, "Unexpected SPNEGO response token bytes.");

                            byte[] encodedResponseToken = SpnegoTokenCodec.EncodeNegTokenResp(responseToken);
                            TestAssertions.Equal((byte)0xA1, encodedResponseToken[0], "SPNEGO response tokens should use the context-specific response wrapper.");

                            SpnegoNegTokenResp decodedResponseToken = SpnegoTokenCodec.DecodeNegTokenResp(encodedResponseToken);
                            TestAssertions.Equal(SpnegoNegState.AcceptIncomplete, decodedResponseToken.NegotiationState!.Value, "The SPNEGO response state changed during round-trip.");
                            TestAssertions.Equal(SpnegoMechanismOid.Ntlm, decodedResponseToken.SupportedMechanism, "The SPNEGO selected mechanism changed during round-trip.");
                            TestAssertions.SequenceEqual(Hex("05060708"), decodedResponseToken.ResponseToken!, "The SPNEGO response token changed during round-trip.");

                            SpnegoNegTokenResp rejectedResponseToken = SpnegoMechanismNegotiator.CreateNegotiationResponse(
                                request: decodedInitToken,
                                supportedMechanisms: new string[] { SpnegoMechanismOid.MicrosoftKerberos });
                            TestAssertions.Equal(SpnegoNegState.Reject, rejectedResponseToken.NegotiationState!.Value, "Unsupported SPNEGO offers should be rejected.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "MessageSignersMatchKnownVectorsAndFactorySelection",
                        displayName: "Message signers match known vectors and the factory selects the negotiated algorithm",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            IMessageSigner hmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
                            byte[] hmacSignature = hmacSigner.Sign(
                                message: Encoding.ASCII.GetBytes("Hi There"),
                                signingKey: CreateRepeatedByteArray(0x0B, 20),
                                nonce: ReadOnlySpan<byte>.Empty);
                            TestAssertions.Equal(SigningAlgorithmId.HmacSha256, hmacSigner.AlgorithmId, "Unexpected HMAC-SHA256 signer algorithm identifier.");
                            TestAssertions.False(hmacSigner.RequiresNonce, "The HMAC-SHA256 signer should not require a nonce.");
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.signing.hmac-sha256"),
                                hmacSignature,
                                "The SMB HMAC-SHA256 signature vector changed.");
                            TestAssertions.True(
                                hmacSigner.Verify(Encoding.ASCII.GetBytes("Hi There"), CreateRepeatedByteArray(0x0B, 20), ReadOnlySpan<byte>.Empty, hmacSignature),
                                "The HMAC-SHA256 signer should verify its own signature.");

                            byte[] aesCmacKey = Hex("2B7E151628AED2A6ABF7158809CF4F3C");
                            byte[] aesCmacMessage = Hex("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710");
                            byte[] aesCmacSignature = AesCmac.ComputeMac(aesCmacKey, aesCmacMessage);
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.signing.aes-cmac"),
                                aesCmacSignature,
                                "The AES-CMAC known-answer vector changed.");

                            IMessageSigner aesCmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            TestAssertions.Equal(SigningAlgorithmId.AesCmac, aesCmacSigner.AlgorithmId, "Unexpected AES-CMAC signer algorithm identifier.");
                            TestAssertions.False(aesCmacSigner.RequiresNonce, "The AES-CMAC signer should not require a nonce.");
                            TestAssertions.SequenceEqual(aesCmacSignature, aesCmacSigner.Sign(aesCmacMessage, aesCmacKey, ReadOnlySpan<byte>.Empty), "The AES-CMAC signer changed the CMAC output.");

                            IMessageSigner aesGmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesGmac);
                            TestAssertions.Equal(SigningAlgorithmId.AesGmac, aesGmacSigner.AlgorithmId, "Unexpected AES-GMAC signer algorithm identifier.");
                            TestAssertions.True(aesGmacSigner.RequiresNonce, "The AES-GMAC signer should require a nonce.");
                            TestAssertions.Equal(16, aesGmacSigner.SignatureLength, "The AES-GMAC signer should produce 16-byte signatures.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "HkdfAndCounterModeKdfMatchKnownVectors",
                        displayName: "HKDF and counter-mode SMB key derivation match known vectors",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] hkdfInputKeyMaterial = Hex("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B");
                            byte[] hkdfSalt = Hex("000102030405060708090A0B0C");
                            byte[] hkdfInfo = Hex("F0F1F2F3F4F5F6F7F8F9");
                            byte[] expectedPrk = GoldenVectorStore.GetBytes("core.security.hkdf.prk");
                            byte[] expectedOkm = GoldenVectorStore.GetBytes("core.security.hkdf.okm");

                            byte[] actualPrk = HkdfSha256.Extract(hkdfInputKeyMaterial, hkdfSalt);
                            byte[] actualOkmFromExpand = HkdfSha256.Expand(expectedPrk, hkdfInfo, 42);
                            byte[] actualOkmFromDerive = HkdfSha256.DeriveKey(hkdfInputKeyMaterial, hkdfSalt, hkdfInfo, 42);

                            TestAssertions.SequenceEqual(expectedPrk, actualPrk, "The HKDF-Extract vector changed.");
                            TestAssertions.SequenceEqual(expectedOkm, actualOkmFromExpand, "The HKDF-Expand vector changed.");
                            TestAssertions.SequenceEqual(expectedOkm, actualOkmFromDerive, "The HKDF combined derive vector changed.");

                            CounterModeKeyDerivationProvider provider = new CounterModeKeyDerivationProvider();
                            byte[] smb30SigningKey = provider.DeriveKey(
                                sessionSecret: CreateRepeatedByteArray(0x55, 16),
                                label: Encoding.ASCII.GetBytes("SMB2AESCMAC\0"),
                                context: Encoding.ASCII.GetBytes("SmbSign\0"),
                                outputLength: 16);
                            TestAssertions.SequenceEqual(
                                GoldenVectorStore.GetBytes("core.security.hkdf.smb30-signing-key"),
                                smb30SigningKey,
                                "The SMB counter-mode signing-key vector changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SmbSessionKeyDerivationMatchesDialectAndCipherRules",
                        displayName: "SMB session subkeys match dialect labels, contexts, and cipher-length rules",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            SmbSessionKeySet smb30KeySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = CreateRepeatedByteArray(0x55, 16),
                                    Dialect = SmbDialect.Smb30,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Ccm
                                });
                            TestAssertions.SequenceEqual(Hex("A2F3731F7E58FDAF7E6DE4871BB7D7D3"), smb30KeySet.SigningKey, "The SMB 3.0 signing key changed.");
                            TestAssertions.SequenceEqual(Hex("E88F948B20805C86BEB4584CB58DC16A"), smb30KeySet.ApplicationKey, "The SMB 3.0 application key changed.");
                            TestAssertions.SequenceEqual(Hex("A91ADF01E344C4319BF664CFA7C70905"), smb30KeySet.EncryptionKey, "The SMB 3.0 encryption key changed.");
                            TestAssertions.SequenceEqual(Hex("FC74A0A2CA6E60B65E2B93CD6863B138"), smb30KeySet.DecryptionKey, "The SMB 3.0 decryption key changed.");

                            SmbSessionKeySet smb311Aes128KeySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = CreateRepeatedByteArray(0x55, 16),
                                    Dialect = SmbDialect.Smb311,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes128Gcm,
                                    PreauthIntegrityHash = CreateSequentialByteArray(64)
                                });
                            TestAssertions.SequenceEqual(Hex("2826DB04880B2879DDC7CE91EC5277A7"), smb311Aes128KeySet.SigningKey, "The SMB 3.1.1 AES-128 signing key changed.");
                            TestAssertions.SequenceEqual(Hex("91C53D0EED81519D539D2800434A2293"), smb311Aes128KeySet.ApplicationKey, "The SMB 3.1.1 AES-128 application key changed.");
                            TestAssertions.SequenceEqual(Hex("89479974D6E3217E9185FD27E39C8DA2"), smb311Aes128KeySet.EncryptionKey, "The SMB 3.1.1 AES-128 encryption key changed.");
                            TestAssertions.SequenceEqual(Hex("1974E6587A668A8F215393970CECF616"), smb311Aes128KeySet.DecryptionKey, "The SMB 3.1.1 AES-128 decryption key changed.");

                            SmbSessionKeySet smb311Aes256KeySet = SmbSessionKeyDerivation.DeriveKeys(
                                new SmbKeyDerivationInputs
                                {
                                    SessionKey = CreateRepeatedByteArray(0x55, 16),
                                    FullSessionKey = CreateSequentialByteArray(32),
                                    Dialect = SmbDialect.Smb311,
                                    CipherAlgorithmId = SmbCipherAlgorithmId.Aes256Gcm,
                                    PreauthIntegrityHash = CreateSequentialByteArray(64)
                                });
                            TestAssertions.SequenceEqual(Hex("5C2A51D834DFBCFA4B53286B3C7CAAC1AE47F2DFDC05A08C2379987CDC08788A"), smb311Aes256KeySet.SigningKey, "The SMB 3.1.1 AES-256 signing key changed.");
                            TestAssertions.SequenceEqual(Hex("D4E23809E89E44ADEC7AEE207C054699D67EED2A261D2DEEE63BF0C229D5FB49"), smb311Aes256KeySet.ApplicationKey, "The SMB 3.1.1 AES-256 application key changed.");
                            TestAssertions.SequenceEqual(Hex("53F8B2FB513A90F5231F5AC12BA0A24B9EED8F6E80596136560F1B0003E8D2AE"), smb311Aes256KeySet.EncryptionKey, "The SMB 3.1.1 AES-256 encryption key changed.");
                            TestAssertions.SequenceEqual(Hex("E568DE865AE188F20138931C5423898FC0D5E94FA094B72D474FC56CF5703DB6"), smb311Aes256KeySet.DecryptionKey, "The SMB 3.1.1 AES-256 decryption key changed.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "AeadWrappersAndGmacMatchVectorsAndDetectTampering",
                        displayName: "GMAC and AEAD wrappers match vectors and detect payload tampering",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            byte[] gcmKey = Hex("FEFFE9928665731C6D6A8F9467308308");
                            byte[] gcmNonce = Hex("CAFEBABEFACEDBADDECAF888");
                            byte[] gcmPlaintext = Hex("D9313225F88406E5A55909C5AFF5269A86A7A9531534F7DA2E4C303D8A318A721C3C0C95956809532FCF0E2449A6B525B16AEDF5AA0DE657BA637B391AAFD255");
                            byte[] gcmAssociatedData = Hex("3AD77BB40D7A3660A89ECAF32466EF97F5D3D58503B9699DE785895A96FDBAAF43B1CD7F598ECE23881B00E3ED0306887B0C785E27E8AD3F8223207104725DD4");
                            byte[] expectedGmac = GoldenVectorStore.GetBytes("core.security.aead.gmac");
                            byte[] expectedGcmCiphertext = GoldenVectorStore.GetBytes("core.security.aead.gcm-ciphertext");
                            byte[] expectedGcmTag = GoldenVectorStore.GetBytes("core.security.aead.gcm-tag");

                            byte[] gmac = AesGmac.ComputeMac(gcmKey, gcmNonce, gcmAssociatedData);
                            TestAssertions.SequenceEqual(expectedGmac, gmac, "The AES-GMAC vector changed.");

                            IMessageSigner gmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesGmac);
                            TestAssertions.SequenceEqual(expectedGmac, gmacSigner.Sign(gcmAssociatedData, gcmKey, gcmNonce), "The AES-GMAC signer changed the NIST vector.");
                            TestAssertions.True(gmacSigner.Verify(gcmAssociatedData, gcmKey, gcmNonce, expectedGmac), "The AES-GMAC signer should verify the known-answer vector.");

                            AeadCipherResult gcmCipherResult = AesGcmCipher.Encrypt(gcmKey, gcmNonce, gcmPlaintext, Array.Empty<byte>());
                            TestAssertions.SequenceEqual(expectedGcmCiphertext, gcmCipherResult.Ciphertext, "The AES-GCM ciphertext vector changed.");
                            TestAssertions.SequenceEqual(expectedGcmTag, gcmCipherResult.AuthenticationTag, "The AES-GCM tag vector changed.");
                            TestAssertions.SequenceEqual(gcmPlaintext, AesGcmCipher.Decrypt(gcmKey, gcmNonce, gcmCipherResult.Ciphertext, gcmCipherResult.AuthenticationTag, Array.Empty<byte>()), "The AES-GCM decrypt path changed the plaintext.");

                            byte[] ccmKey = Hex("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
                            byte[] ccmNonce = Hex("00000003020100A0A1A2A3A4A5");
                            byte[] ccmAssociatedData = Hex("0001020304050607");
                            byte[] ccmPlaintext = Hex("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
                            AeadCipherResult ccmCipherResult = AesCcmCipher.Encrypt(ccmKey, ccmNonce, ccmPlaintext, ccmAssociatedData, tagLength: 8);
                            TestAssertions.SequenceEqual(GoldenVectorStore.GetBytes("core.security.aead.ccm-ciphertext"), ccmCipherResult.Ciphertext, "The AES-CCM ciphertext vector changed.");
                            TestAssertions.SequenceEqual(GoldenVectorStore.GetBytes("core.security.aead.ccm-tag"), ccmCipherResult.AuthenticationTag, "The AES-CCM tag vector changed.");
                            TestAssertions.SequenceEqual(ccmPlaintext, AesCcmCipher.Decrypt(ccmKey, ccmNonce, ccmCipherResult.Ciphertext, ccmCipherResult.AuthenticationTag, ccmAssociatedData), "The AES-CCM decrypt path changed the plaintext.");

                            byte[] corruptedGcmTag = CreateMutatedCopy(gcmCipherResult.AuthenticationTag);
                            TestAssertions.Throws<CryptographicException>(
                                () => AesGcmCipher.Decrypt(gcmKey, gcmNonce, gcmCipherResult.Ciphertext, corruptedGcmTag, Array.Empty<byte>()),
                                "Corrupt AES-GCM tags should fail authentication.");
                            byte[] corruptedCcmTag = CreateMutatedCopy(ccmCipherResult.AuthenticationTag);
                            TestAssertions.Throws<CryptographicException>(
                                () => AesCcmCipher.Decrypt(ccmKey, ccmNonce, ccmCipherResult.Ciphertext, corruptedCcmTag, ccmAssociatedData),
                                "Corrupt AES-CCM tags should fail authentication.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Security",
                        caseId: "SecurityPrimitivesRejectInvalidTokensMicsAndSignatures",
                        displayName: "Security primitives reject invalid tokens, MICs, signatures, and unsupported key material",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            NtlmV2ChallengeResponseSet responseSet = NtlmV2Authentication.CreateChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                clientChallenge: CreateMicrosoftNtlmV2ClientChallenge());
                            byte[] mutatedLmResponse = CreateMutatedCopy(responseSet.LmChallengeResponse);
                            bool verified = NtlmV2Authentication.TryVerifyChallengeResponseSet(
                                password: "Password",
                                userName: "User",
                                userDomain: "Domain",
                                serverChallenge: Hex("0123456789ABCDEF"),
                                ntChallengeResponse: responseSet.NtChallengeResponse.ToByteArray(),
                                lmChallengeResponse: mutatedLmResponse,
                                verifiedResponseSet: out NtlmV2ChallengeResponseSet? _);
                            TestAssertions.False(verified, "Corrupt LMv2 responses should not verify.");

                            byte[] validMic = NtlmMessageIntegrityCode.Compute(
                                exportedSessionKey: CreateRepeatedByteArray(0x55, 16),
                                negotiateMessage: new byte[] { 0x01, 0x02, 0x03 },
                                challengeMessage: new byte[] { 0x04, 0x05 },
                                authenticateMessageWithZeroMic: new byte[] { 0x06, 0x07, 0x08 });
                            byte[] mutatedMic = CreateMutatedCopy(validMic);
                            TestAssertions.False(
                                NtlmMessageIntegrityCode.Verify(CreateRepeatedByteArray(0x55, 16), new byte[] { 0x01, 0x02, 0x03 }, new byte[] { 0x04, 0x05 }, new byte[] { 0x06, 0x07, 0x08 }, mutatedMic),
                                "Corrupt NTLM MIC values should not verify.");

                            IMessageSigner hmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.HmacSha256);
                            byte[] hmacSignature = hmacSigner.Sign(Encoding.ASCII.GetBytes("sign me"), Hex("00112233445566778899AABBCCDDEEFF"), ReadOnlySpan<byte>.Empty);
                            TestAssertions.False(
                                hmacSigner.Verify(Encoding.ASCII.GetBytes("sign me"), Hex("00112233445566778899AABBCCDDEEFF"), ReadOnlySpan<byte>.Empty, CreateMutatedCopy(hmacSignature)),
                                "Corrupt HMAC-SHA256 signatures should not verify.");

                            IMessageSigner cmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesCmac);
                            byte[] cmacSignature = cmacSigner.Sign(Hex("11223344556677889900AABBCCDDEEFF"), Hex("2B7E151628AED2A6ABF7158809CF4F3C"), ReadOnlySpan<byte>.Empty);
                            TestAssertions.False(
                                cmacSigner.Verify(Hex("11223344556677889900AABBCCDDEEFF"), Hex("2B7E151628AED2A6ABF7158809CF4F3C"), ReadOnlySpan<byte>.Empty, CreateMutatedCopy(cmacSignature)),
                                "Corrupt AES-CMAC signatures should not verify.");

                            IMessageSigner gmacSigner = MessageSignerFactory.Create(SigningAlgorithmId.AesGmac);
                            byte[] gmacSignature = gmacSigner.Sign(Hex("AABBCCDD"), Hex("FEFFE9928665731C6D6A8F9467308308"), Hex("CAFEBABEFACEDBADDECAF888"));
                            TestAssertions.False(
                                gmacSigner.Verify(Hex("AABBCCDD"), Hex("FEFFE9928665731C6D6A8F9467308308"), Hex("CAFEBABEFACEDBADDECAF888"), CreateMutatedCopy(gmacSignature)),
                                "Corrupt AES-GMAC signatures should not verify.");

                            TestAssertions.Throws<ProtocolEncodingException>(
                                () => SpnegoTokenCodec.DecodeNegTokenInit(Hex("600306012A")),
                                "Malformed SPNEGO NegTokenInit payloads should fail decoding.");
                            TestAssertions.Throws<ArgumentException>(
                                () => SmbSessionKeyDerivation.DeriveEncryptionKey(
                                    new SmbKeyDerivationInputs
                                    {
                                        SessionKey = CreateRepeatedByteArray(0x55, 16),
                                        Dialect = SmbDialect.Smb311,
                                        CipherAlgorithmId = SmbCipherAlgorithmId.Aes256Gcm,
                                        PreauthIntegrityHash = CreateSequentialByteArray(64)
                                    }),
                                "SMB 3.1.1 AES-256 encryption derivation should require a full session key.");
                            return Task.CompletedTask;
                        })
                });
        }

        /// <summary>
        /// Build the transport foundation suite.
        /// </summary>
        /// <returns>Suite descriptor.</returns>
        public static TestSuiteDescriptor TransportFoundationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "Core.Transport",
                displayName: "Transport codec and pipe foundations",
                cases: new List<TestCaseDescriptor>
                {
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "TransportOptionsClampCapacities",
                        displayName: "Transport connection options clamp capacities",
                        executeAsync: token =>
                        {
                            token.ThrowIfCancellationRequested();

                            FramedPipeConnectionOptions options = new FramedPipeConnectionOptions
                            {
                                InboundFrameCapacity = 0,
                                OutboundFrameCapacity = 10000
                            };

                            TestAssertions.Equal(1, options.InboundFrameCapacity, "Inbound capacity should clamp to the minimum.");
                            TestAssertions.Equal(4096, options.OutboundFrameCapacity, "Outbound capacity should clamp to the maximum.");
                            return Task.CompletedTask;
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "FrameProtocolsRoundTripAndRejectMalformedInputs",
                        displayName: "Frame protocols round-trip payloads and reject malformed inputs",
                        executeAsync: async token =>
                        {
                            using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                            timeoutSource.CancelAfter(TimeSpan.FromSeconds(5));
                            CancellationToken timeoutToken = timeoutSource.Token;

                            byte[] directPayload = new byte[] { 0x01, 0x02, 0x03 };
                            DirectTcpFrameProtocol directProtocol = new DirectTcpFrameProtocol();
                            Pipe directPipe = new Pipe();
                            await directProtocol.WriteFrameAsync(directPipe.Writer, directPayload, timeoutToken).ConfigureAwait(false);
                            await directPipe.Writer.FlushAsync(timeoutToken).ConfigureAwait(false);
                            await directPipe.Writer.CompleteAsync().ConfigureAwait(false);
                            byte[] decodedDirectPayload = await ReadFrameFromPipeAsync(directPipe.Reader, directProtocol, timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(directPayload, decodedDirectPayload, "Direct TCP frame protocol changed the payload.");
                            await directPipe.Reader.CompleteAsync().ConfigureAwait(false);

                            byte[] partialDirectFrame = new byte[DirectTcpFrameHeader.Size];
                            byte[] encodedDirectFrame = CreateDirectTcpFrame(directPayload);
                            Array.Copy(encodedDirectFrame, partialDirectFrame, partialDirectFrame.Length);
                            bool hasDirectFrame = directProtocol.TryReadFrame(new ReadOnlySequence<byte>(partialDirectFrame), out byte[]? directPartialPayload, out long directPartialConsumed);
                            TestAssertions.False(hasDirectFrame, "A partial Direct TCP frame should not decode.");
                            TestAssertions.True(directPartialPayload == null, "A partial Direct TCP frame should not return a payload.");
                            TestAssertions.Equal(0L, directPartialConsumed, "A partial Direct TCP frame should not consume bytes.");

                            DirectTcpFrameProtocol constrainedDirectProtocol = new DirectTcpFrameProtocol
                            {
                                MaximumFrameLength = 1024
                            };
                            byte[] oversizedDirectFrame = CreateDirectTcpFrame(new byte[1025]);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () =>
                                {
                                    constrainedDirectProtocol.TryReadFrame(new ReadOnlySequence<byte>(oversizedDirectFrame), out byte[]? _, out long _);
                                },
                                "An oversized Direct TCP frame should fail validation.");

                            byte[] netBiosPayload = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD };
                            NetBiosSessionServiceFrameProtocol netBiosProtocol = new NetBiosSessionServiceFrameProtocol
                            {
                                MessageType = NetBiosSessionMessageType.SessionMessage
                            };

                            Pipe netBiosPipe = new Pipe();
                            await netBiosProtocol.WriteFrameAsync(netBiosPipe.Writer, netBiosPayload, timeoutToken).ConfigureAwait(false);
                            await netBiosPipe.Writer.FlushAsync(timeoutToken).ConfigureAwait(false);
                            await netBiosPipe.Writer.CompleteAsync().ConfigureAwait(false);
                            byte[] decodedNetBiosPayload = await ReadFrameFromPipeAsync(netBiosPipe.Reader, netBiosProtocol, timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(netBiosPayload, decodedNetBiosPayload, "NetBIOS frame protocol changed the payload.");
                            await netBiosPipe.Reader.CompleteAsync().ConfigureAwait(false);

                            byte[] partialNetBiosFrame = new byte[NetBiosSessionServiceHeader.Size];
                            byte[] encodedNetBiosFrame = CreateNetBiosFrame(NetBiosSessionMessageType.SessionMessage, netBiosPayload);
                            Array.Copy(encodedNetBiosFrame, partialNetBiosFrame, partialNetBiosFrame.Length);
                            bool hasNetBiosFrame = netBiosProtocol.TryReadFrame(new ReadOnlySequence<byte>(partialNetBiosFrame), out byte[]? netBiosPartialPayload, out long netBiosPartialConsumed);
                            TestAssertions.False(hasNetBiosFrame, "A partial NetBIOS frame should not decode.");
                            TestAssertions.True(netBiosPartialPayload == null, "A partial NetBIOS frame should not return a payload.");
                            TestAssertions.Equal(0L, netBiosPartialConsumed, "A partial NetBIOS frame should not consume bytes.");

                            NetBiosSessionServiceFrameProtocol constrainedNetBiosProtocol = new NetBiosSessionServiceFrameProtocol
                            {
                                MaximumFrameLength = 1024
                            };
                            byte[] oversizedNetBiosFrame = CreateNetBiosFrame(NetBiosSessionMessageType.SessionMessage, new byte[1025]);

                            TestAssertions.Throws<ProtocolValidationException>(
                                () =>
                                {
                                    constrainedNetBiosProtocol.TryReadFrame(new ReadOnlySequence<byte>(oversizedNetBiosFrame), out byte[]? _, out long _);
                                },
                                "An oversized NetBIOS frame should fail validation.");
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "FramedPipeConnectionTransfersFrames",
                        displayName: "Framed pipe connections transfer frames and enforce lifecycle rules",
                        executeAsync: async token =>
                        {
                            using CancellationTokenSource timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(token);
                            timeoutSource.CancelAfter(TimeSpan.FromSeconds(5));
                            CancellationToken timeoutToken = timeoutSource.Token;

                            Pipe inboundPipe = new Pipe();
                            Pipe outboundPipe = new Pipe();

                            await using FramedPipeConnection connection = new FramedPipeConnection(
                                inboundPipe.Reader,
                                outboundPipe.Writer,
                                new DirectTcpFrameProtocol(),
                                new FramedPipeConnectionOptions
                                {
                                    InboundFrameCapacity = 2,
                                    OutboundFrameCapacity = 2
                                });

                            TestAssertions.Throws<InvalidOperationException>(
                                () => connection.CompleteWrites(),
                                "Completing writes before the connection starts should fail.");

                            connection.Start();
                            TestAssertions.Throws<InvalidOperationException>(
                                () => connection.Start(),
                                "Starting the connection twice should fail.");

                            byte[] inboundPayload = new byte[] { 0x31, 0x32, 0x33, 0x34 };
                            byte[] inboundFrame = CreateDirectTcpFrame(inboundPayload);
                            await inboundPipe.Writer.WriteAsync(inboundFrame, timeoutToken).ConfigureAwait(false);
                            await inboundPipe.Writer.CompleteAsync().ConfigureAwait(false);

                            byte[] receivedInboundPayload = await connection.ReadAsync(timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(inboundPayload, receivedInboundPayload, "The framed connection returned an unexpected inbound payload.");

                            byte[] outboundPayload = new byte[] { 0x44, 0x45, 0x46 };
                            await connection.WriteAsync(outboundPayload, timeoutToken).ConfigureAwait(false);
                            connection.CompleteWrites();

                            byte[] receivedOutboundPayload = await ReadFrameFromPipeAsync(outboundPipe.Reader, new DirectTcpFrameProtocol(), timeoutToken).ConfigureAwait(false);
                            TestAssertions.SequenceEqual(outboundPayload, receivedOutboundPayload, "The framed connection wrote an unexpected outbound payload.");

                            await connection.Completion.ConfigureAwait(false);
                            await outboundPipe.Reader.CompleteAsync().ConfigureAwait(false);
                        }),
                    new TestCaseDescriptor(
                        suiteId: "Core.Transport",
                        caseId: "FramedPipeConnectionSuppressesExpectedSocketAbortDuringDispose",
                        displayName: "Framed pipe connections suppress expected socket-abort cleanup faults during dispose",
                        executeAsync: async token =>
                        {
                            token.ThrowIfCancellationRequested();

                            Pipe inboundPipe = new Pipe();
                            Pipe outboundPipe = new Pipe();

                            await using FramedPipeConnection connection = new FramedPipeConnection(
                                new ThrowingCompletePipeReader(inboundPipe.Reader),
                                new ThrowingCompletePipeWriter(outboundPipe.Writer),
                                new DirectTcpFrameProtocol());

                            connection.Start();
                            await connection.DisposeAsync().ConfigureAwait(false);
                        })
                });
        }

        private static void AssertDialectPresent(string[] names, string expectedName)
        {
            for (int index = 0; index < names.Length; index++)
            {
                if (StringComparer.Ordinal.Equals(names[index], expectedName))
                {
                    return;
                }
            }

            throw new InvalidOperationException("Expected dialect name was not present: " + expectedName + ".");
        }

        private static Smb1Header CreateValidSmb1Header()
        {
            return new Smb1Header
            {
                Command = Smb1Command.WriteAndX,
                Status = NtStatus.AccessDenied,
                Flags = Smb1HeaderFlags.CaseInsensitive | Smb1HeaderFlags.Reply,
                Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity,
                ProcessIdHigh = 0x1234,
                Signature = new byte[] { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 },
                TreeId = 0x4567,
                ProcessIdLow = 0x89AB,
                UserId = 0xCDEF,
                MultiplexId = 0x2468
            };
        }

        private static Smb2Header CreateValidSmb2Header()
        {
            return new Smb2Header
            {
                CreditCharge = 2,
                Status = NtStatus.BufferTooSmall,
                Command = Smb2Command.QueryInfo,
                CreditRequest = 7,
                Flags = Smb2HeaderFlags.Signed | Smb2HeaderFlags.ServerToRedir,
                NextCommand = 16,
                MessageId = 0x0102030405060708UL,
                ProcessId = 0x0A0B0C0DU,
                TreeId = 0x10203040U,
                SessionId = 0x1122334455667788UL,
                Signature = new byte[] { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F }
            };
        }

        private static Smb2Header CreateCompoundHeader(Smb2Command command, ulong messageId, Smb2HeaderFlags flags = Smb2HeaderFlags.None)
        {
            return new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = command,
                CreditRequest = 1,
                Flags = flags,
                NextCommand = 0,
                MessageId = messageId,
                ProcessId = 0,
                TreeId = 0,
                SessionId = 0,
                Signature = new byte[16]
            };
        }

        private static byte[] CreateDirectTcpFrame(ReadOnlySpan<byte> payload)
        {
            DirectTcpFrameHeader header = new DirectTcpFrameHeader
            {
                Length = payload.Length
            };

            return Combine(header.ToByteArray(), payload);
        }

        private static byte[] CreateNetBiosFrame(NetBiosSessionMessageType messageType, ReadOnlySpan<byte> payload)
        {
            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
            {
                MessageType = messageType,
                Length = payload.Length
            };

            return Combine(header.ToByteArray(), payload);
        }

        private static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
        {
            byte[] combined = new byte[first.Length + second.Length];
            first.CopyTo(combined.AsSpan(0, first.Length));
            second.CopyTo(combined.AsSpan(first.Length, second.Length));
            return combined;
        }

        private static byte[] CreateMicrosoftNtlmV2ClientChallengeBytes()
        {
            return Hex("01010000000000000000000000000000AAAAAAAAAAAAAAAA0000000002000C0044006F006D00610069006E0001000C005300650072007600650072000000000000000000");
        }

        private static NtlmV2ClientChallenge CreateMicrosoftNtlmV2ClientChallenge()
        {
            return NtlmV2ClientChallenge.ReadFrom(CreateMicrosoftNtlmV2ClientChallengeBytes());
        }

        private static byte[] CreateRepeatedByteArray(byte value, int length)
        {
            byte[] buffer = new byte[length];

            for (int index = 0; index < buffer.Length; index++)
            {
                buffer[index] = value;
            }

            return buffer;
        }

        private static byte[] CreateSequentialByteArray(int length)
        {
            byte[] buffer = new byte[length];

            for (int index = 0; index < buffer.Length; index++)
            {
                buffer[index] = (byte)index;
            }

            return buffer;
        }

        private static byte[] CreateMutatedCopy(ReadOnlySpan<byte> value)
        {
            byte[] buffer = value.ToArray();

            if (buffer.Length == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Cannot mutate an empty byte sequence.");
            }

            buffer[buffer.Length - 1] ^= 0x01;
            return buffer;
        }

        private static IReadOnlyList<(string Name, byte[] Baseline, Action<byte[]> Parser)> BuildProtocolMutationCorpus()
        {
            Smb2Header smb2Header = new Smb2Header
            {
                CreditCharge = 0,
                Status = NtStatus.Success,
                Command = Smb2Command.Negotiate,
                CreditRequest = 1,
                Flags = Smb2HeaderFlags.None,
                NextCommand = 0,
                MessageId = 1,
                TreeId = 0,
                SessionId = 0,
                Signature = new byte[16]
            };

            Smb2NegotiateRequest negotiateRequest = new Smb2NegotiateRequest
            {
                SecurityMode = Smb2SecurityMode.SigningEnabled,
                ClientGuid = Guid.Parse("6D8F66FA-6D20-4D4C-B016-A3B3AC02D40F"),
                Dialects = new[] { SmbDialect.Smb2002, SmbDialect.Smb21 }
            };

            Smb2CreateRequest createRequest = new Smb2CreateRequest
            {
                RequestedOplockLevel = Smb2OplockLevel.None,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = 0xC0000000U,
                FileAttributes = ProtocolFileAttributes.Normal,
                ShareAccess = 0x00000007U,
                CreateDisposition = Smb2CreateDisposition.OpenIf,
                CreateOptions = Smb2CreateOptions.NonDirectoryFile,
                Name = "folder\\notes.txt",
                CreateContexts = Array.Empty<byte>()
            };

            Smb2ChangeNotifyRequest changeNotifyRequest = new Smb2ChangeNotifyRequest
            {
                Flags = Smb2ChangeNotifyFlags.WatchTree,
                OutputBufferLength = 4096,
                PersistentFileId = 10,
                VolatileFileId = 11,
                CompletionFilter = FileNotifyChangeFilter.FileName | FileNotifyChangeFilter.LastWrite
            };

            Smb2IoctlRequest ioctlRequest = new Smb2IoctlRequest
            {
                CtlCode = (uint)FsctlCode.SrvEnumerateSnapshots,
                PersistentFileId = 301,
                VolatileFileId = 302,
                MaxInputResponse = 0,
                MaxOutputResponse = 4096,
                Flags = Smb2IoctlFlags.IsFsctl,
                InputBuffer = new byte[] { 0x10, 0x20, 0x30, 0x40 }
            };

            Smb2LeaseBreakAcknowledgment leaseAcknowledgment = new Smb2LeaseBreakAcknowledgment
            {
                LeaseKey = CreateRepeatedByteArray(0x11, 16),
                LeaseState = Smb2LeaseState.None
            };

            Smb2QueryInfoRequest queryInfoRequest = new Smb2QueryInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = FileInformationClass.BasicInformation,
                OutputBufferLength = 128,
                PersistentFileId = 1,
                VolatileFileId = 2,
                InputBuffer = Array.Empty<byte>()
            };

            FileBothDirectoryInformationEntry[] directoryEntries = new[]
            {
                new FileBothDirectoryInformationEntry
                {
                    FileName = "alpha.txt"
                },
                new FileBothDirectoryInformationEntry
                {
                    FileName = "nested"
                }
            };

            Smb2CompoundPacket negotiatePacket = new Smb2CompoundPacket(new[]
            {
                new Smb2CompoundPacketEntry(smb2Header, negotiateRequest.ToByteArray())
            });

            return new List<(string Name, byte[] Baseline, Action<byte[]> Parser)>
            {
                (
                    "DirectTcpFrameHeader",
                    new DirectTcpFrameHeader { Length = 64 }.ToByteArray(),
                    bytes =>
                    {
                        DirectTcpFrameHeader parsedHeader = DirectTcpFrameHeader.ReadFrom(bytes);
                        DirectTcpFrameValidator.Validate(parsedHeader);
                    }),
                (
                    "Smb2Header",
                    smb2Header.ToByteArray(),
                    bytes =>
                    {
                        Smb2Header parsedHeader = Smb2Header.ReadFrom(bytes);
                        Smb2HeaderValidator.Validate(parsedHeader);
                    }),
                (
                    "Smb2NegotiateRequest",
                    negotiateRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2NegotiateRequest parsedRequest = Smb2NegotiateRequest.ReadFrom(bytes);
                        Smb2NegotiateRequestValidator.Validate(parsedRequest);
                    }),
                (
                    "Smb2CreateRequest",
                    createRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2CreateRequest parsedRequest = Smb2CreateRequest.ReadFrom(bytes);
                        Smb2CreateRequestValidator.Validate(parsedRequest);
                    }),
                (
                    "Smb2ChangeNotifyRequest",
                    changeNotifyRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2ChangeNotifyRequest parsedRequest = Smb2ChangeNotifyRequest.ReadFrom(bytes);
                        Smb2ChangeNotifyRequestValidator.Validate(parsedRequest);
                    }),
                (
                    "Smb2IoctlRequest",
                    ioctlRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2IoctlRequest parsedRequest = Smb2IoctlRequest.ReadFrom(bytes);
                        Smb2IoctlRequestValidator.Validate(parsedRequest);
                    }),
                (
                    "Smb2LeaseBreakAcknowledgment",
                    leaseAcknowledgment.ToByteArray(),
                    bytes =>
                    {
                        Smb2LeaseBreakAcknowledgment parsedAcknowledgment = Smb2LeaseBreakAcknowledgment.ReadFrom(bytes);
                        Smb2LeaseBreakAcknowledgmentValidator.Validate(parsedAcknowledgment);
                    }),
                (
                    "Smb2QueryInfoRequest",
                    queryInfoRequest.ToByteArray(),
                    bytes =>
                    {
                        Smb2QueryInfoRequest parsedRequest = Smb2QueryInfoRequest.ReadFrom(bytes);
                        Smb2QueryInfoRequestValidator.Validate(parsedRequest);
                    }),
                (
                    "FileBothDirectoryInformationEntry",
                    FileBothDirectoryInformationEntry.EncodeEntries(directoryEntries),
                    bytes =>
                    {
                        FileBothDirectoryInformationEntry.DecodeEntries(bytes);
                    }),
                (
                    "Smb2CompoundPacket",
                    negotiatePacket.ToByteArray(),
                    bytes =>
                    {
                        Smb2CompoundPacket.ReadFrom(bytes);
                    }),
                (
                    "DfsReferralRequest",
                    new DfsReferralRequest
                    {
                        MaxReferralLevel = 2,
                        RequestPath = @"\labserver\namespace\link"
                    }.ToByteArray(),
                    bytes =>
                    {
                        DfsReferralRequest.ReadFrom(bytes);
                    }),
                (
                    "DfsReferralResponse",
                    new DfsReferralResponse
                    {
                        PathConsumed = 24,
                        HeaderFlags = DfsReferralHeaderFlags.StorageServers,
                        Entries = new[]
                        {
                            new DfsReferralEntryV2
                            {
                                IsRootTarget = false,
                                TimeToLive = 600,
                                DfsPath = @"\labserver\namespace",
                                NetworkAddress = @"\target\share"
                            }
                        }
                    }.ToByteArray(),
                    bytes =>
                    {
                        DfsReferralResponse.ReadFrom(bytes);
                    }),
                (
                    "Smb311NegotiateContextList",
                    Smb2NegotiateContextList.Encode(new[]
                    {
                        new Smb2NegotiateContextEntry
                        {
                            ContextType = Smb2NegotiateContextType.PreauthIntegrityCapabilities,
                            Payload = new PreauthIntegrityCapabilities
                            {
                                HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 },
                                Salt = new byte[] { 0x11, 0x22, 0x33, 0x44 }
                            }.ToByteArray()
                        },
                        new Smb2NegotiateContextEntry
                        {
                            ContextType = Smb2NegotiateContextType.EncryptionCapabilities,
                            Payload = new EncryptionCapabilities
                            {
                                Ciphers = new SmbCipherAlgorithmId[]
                                {
                                    SmbCipherAlgorithmId.Aes256Gcm,
                                    SmbCipherAlgorithmId.Aes128Gcm,
                                    SmbCipherAlgorithmId.Aes128Ccm
                                }
                            }.ToByteArray()
                        }
                    }),
                    bytes =>
                    {
                        Smb2NegotiateContextList.Decode(bytes, 2);
                    })
            };
        }

        private static byte[] Hex(string value)
        {
            return Convert.FromHexString(value.Replace(" ", string.Empty));
        }

        private static async Task<byte[]> ReadFrameFromPipeAsync(PipeReader reader, IFrameProtocol frameProtocol, CancellationToken cancellationToken)
        {
            while (true)
            {
                ReadResult readResult = await reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                ReadOnlySequence<byte> buffer = readResult.Buffer;

                if (frameProtocol.TryReadFrame(buffer, out byte[]? payload, out long bytesConsumed))
                {
                    if (payload == null)
                    {
                        throw new InvalidOperationException("The frame protocol returned a null payload.");
                    }

                    SequencePosition consumedPosition = buffer.GetPosition(bytesConsumed);
                    reader.AdvanceTo(consumedPosition, buffer.End);
                    return payload;
                }

                reader.AdvanceTo(buffer.Start, buffer.End);

                if (readResult.IsCompleted)
                {
                    throw new InvalidOperationException("The pipe completed before a full frame was available.");
                }
            }
        }

        private sealed class ThrowingCompletePipeReader : PipeReader
        {
            private readonly PipeReader _InnerReader;

            public ThrowingCompletePipeReader(PipeReader innerReader)
            {
                _InnerReader = innerReader ?? throw new ArgumentNullException(nameof(innerReader));
            }

            public override void AdvanceTo(SequencePosition consumed)
            {
                _InnerReader.AdvanceTo(consumed);
            }

            public override void AdvanceTo(SequencePosition consumed, SequencePosition examined)
            {
                _InnerReader.AdvanceTo(consumed, examined);
            }

            public override void CancelPendingRead()
            {
                _InnerReader.CancelPendingRead();
            }

            public override void Complete(Exception? exception = null)
            {
                throw new IOException("Simulated reader completion fault during expected cancellation.");
            }

            public override ValueTask CompleteAsync(Exception? exception = null)
            {
                return ValueTask.FromException(new IOException("Simulated reader completion fault during expected cancellation."));
            }

            public override ValueTask<ReadResult> ReadAsync(CancellationToken cancellationToken = default)
            {
                return _InnerReader.ReadAsync(cancellationToken);
            }

            public override bool TryRead(out ReadResult result)
            {
                return _InnerReader.TryRead(out result);
            }
        }

        private sealed class ThrowingCompletePipeWriter : PipeWriter
        {
            private readonly PipeWriter _InnerWriter;

            public ThrowingCompletePipeWriter(PipeWriter innerWriter)
            {
                _InnerWriter = innerWriter ?? throw new ArgumentNullException(nameof(innerWriter));
            }

            public override void Advance(int bytes)
            {
                _InnerWriter.Advance(bytes);
            }

            public override void CancelPendingFlush()
            {
                _InnerWriter.CancelPendingFlush();
            }

            public override void Complete(Exception? exception = null)
            {
                throw new IOException("Simulated writer completion fault during expected cancellation.");
            }

            public override ValueTask CompleteAsync(Exception? exception = null)
            {
                return ValueTask.FromException(new IOException("Simulated writer completion fault during expected cancellation."));
            }

            public override ValueTask<FlushResult> FlushAsync(CancellationToken cancellationToken = default)
            {
                return _InnerWriter.FlushAsync(cancellationToken);
            }

            public override Memory<byte> GetMemory(int sizeHint = 0)
            {
                return _InnerWriter.GetMemory(sizeHint);
            }

            public override Span<byte> GetSpan(int sizeHint = 0)
            {
                return _InnerWriter.GetSpan(sizeHint);
            }
        }
    }
}
