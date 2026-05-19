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
    internal static class PrimitiveCodecSuiteBuilder
    {
        internal static TestSuiteDescriptor Build()
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
    }
}
