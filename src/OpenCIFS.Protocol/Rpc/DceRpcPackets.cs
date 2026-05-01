namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    [Flags]
    internal enum DceRpcPacketFlags : byte
    {
        None = 0x00,
        FirstFragment = 0x01,
        LastFragment = 0x02
    }

    internal enum DceRpcPacketType : byte
    {
        Request = 0x00,
        Response = 0x02,
        Fault = 0x03,
        Bind = 0x0B,
        BindAck = 0x0C
    }

    internal static class DceRpcConstants
    {
        internal static readonly Guid NdrTransferSyntax = new Guid("8A885D04-1CEB-11C9-9FE8-08002B104860");
        internal static readonly Guid SrvsvcInterface = new Guid("4B324FC8-1670-01D3-1278-5A47BF6EE188");

        internal const ushort DefaultFragmentSize = 4280;
        internal const ushort NdrTransferSyntaxVersionMajor = 2;
        internal const ushort NdrTransferSyntaxVersionMinor = 0;
        internal const ushort SrvsvcInterfaceVersionMajor = 3;
        internal const ushort SrvsvcInterfaceVersionMinor = 0;
        internal const ushort SrvsvcContextId = 0;
    }

    internal sealed class DceRpcBindRequest
    {
        public uint CallId { get; set; } = 1;

        public ushort MaximumTransmitFragment { get; set; } = DceRpcConstants.DefaultFragmentSize;

        public ushort MaximumReceiveFragment { get; set; } = DceRpcConstants.DefaultFragmentSize;

        public ushort ContextId { get; set; } = DceRpcConstants.SrvsvcContextId;

        public Guid InterfaceId { get; set; } = DceRpcConstants.SrvsvcInterface;

        public ushort InterfaceVersionMajor { get; set; } = DceRpcConstants.SrvsvcInterfaceVersionMajor;

        public ushort InterfaceVersionMinor { get; set; } = DceRpcConstants.SrvsvcInterfaceVersionMinor;

        public Guid TransferSyntaxId { get; set; } = DceRpcConstants.NdrTransferSyntax;

        public ushort TransferSyntaxVersionMajor { get; set; } = DceRpcConstants.NdrTransferSyntaxVersionMajor;

        public ushort TransferSyntaxVersionMinor { get; set; } = DceRpcConstants.NdrTransferSyntaxVersionMinor;

        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte(0x05);
            writer.WriteByte(0x00);
            writer.WriteByte((byte)DceRpcPacketType.Bind);
            writer.WriteByte((byte)(DceRpcPacketFlags.FirstFragment | DceRpcPacketFlags.LastFragment));
            writer.WriteByte(0x10);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt32(CallId);
            writer.WriteUInt16(MaximumTransmitFragment);
            writer.WriteUInt16(MaximumReceiveFragment);
            writer.WriteUInt32(0);
            writer.WriteByte(0x01);
            writer.WriteByte(0x00);
            writer.WriteUInt16(0);
            writer.WriteUInt16(ContextId);
            writer.WriteByte(0x01);
            writer.WriteByte(0x00);
            writer.WriteGuid(InterfaceId);
            writer.WriteUInt16(InterfaceVersionMajor);
            writer.WriteUInt16(InterfaceVersionMinor);
            writer.WriteGuid(TransferSyntaxId);
            writer.WriteUInt16(TransferSyntaxVersionMajor);
            writer.WriteUInt16(TransferSyntaxVersionMinor);
            byte[] packet = writer.ToArray();
            DceRpcEncoding.FinalizePacket(packet);
            return packet;
        }

        public static DceRpcBindRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 44)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete DCE/RPC bind request.");
            }

            LittleEndianReader headerReader = new LittleEndianReader(buffer);
            DceRpcEncoding.ValidateCommonHeader(headerReader, DceRpcPacketType.Bind, buffer.Length, out ushort fragmentLength);
            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(16, fragmentLength - 16));
            DceRpcBindRequest bindRequest = new DceRpcBindRequest
            {
                MaximumTransmitFragment = reader.ReadUInt16(),
                MaximumReceiveFragment = reader.ReadUInt16(),
            };
            _ = reader.ReadUInt32();
            byte contextCount = reader.ReadByte();
            _ = reader.ReadByte();
            _ = reader.ReadUInt16();

            if (contextCount == 0)
            {
                throw new ProtocolEncodingException("The DCE/RPC bind request does not contain any presentation contexts.");
            }

            bindRequest.ContextId = reader.ReadUInt16();
            byte transferItemCount = reader.ReadByte();
            _ = reader.ReadByte();

            if (transferItemCount == 0)
            {
                throw new ProtocolEncodingException("The DCE/RPC bind request does not contain any transfer syntaxes.");
            }

            bindRequest.InterfaceId = reader.ReadGuid();
            bindRequest.InterfaceVersionMajor = reader.ReadUInt16();
            bindRequest.InterfaceVersionMinor = reader.ReadUInt16();
            bindRequest.TransferSyntaxId = reader.ReadGuid();
            bindRequest.TransferSyntaxVersionMajor = reader.ReadUInt16();
            bindRequest.TransferSyntaxVersionMinor = reader.ReadUInt16();
            return bindRequest;
        }
    }

    internal sealed class DceRpcBindAck
    {
        public uint CallId { get; set; }

        public ushort MaximumTransmitFragment { get; set; } = DceRpcConstants.DefaultFragmentSize;

        public ushort MaximumReceiveFragment { get; set; } = DceRpcConstants.DefaultFragmentSize;

        public uint AssociationGroupId { get; set; }

        public ushort ResultCode { get; set; }

        public ushort ReasonCode { get; set; }

        public Guid TransferSyntaxId { get; set; } = DceRpcConstants.NdrTransferSyntax;

        public ushort TransferSyntaxVersionMajor { get; set; } = DceRpcConstants.NdrTransferSyntaxVersionMajor;

        public ushort TransferSyntaxVersionMinor { get; set; } = DceRpcConstants.NdrTransferSyntaxVersionMinor;

        public static DceRpcBindAck ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 36)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete DCE/RPC bind acknowledgment.");
            }

            LittleEndianReader headerReader = new LittleEndianReader(buffer);
            DceRpcEncoding.ValidateCommonHeader(headerReader, DceRpcPacketType.BindAck, buffer.Length, out ushort fragmentLength);
            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(16, fragmentLength - 16));
            DceRpcBindAck bindAck = new DceRpcBindAck
            {
                MaximumTransmitFragment = reader.ReadUInt16(),
                MaximumReceiveFragment = reader.ReadUInt16(),
                AssociationGroupId = reader.ReadUInt32()
            };

            ushort securityAddressLength = reader.ReadUInt16();
            reader.Skip(securityAddressLength);
            DceRpcEncoding.SkipReaderAlignment(reader, 4);
            byte resultCount = reader.ReadByte();
            reader.Skip(3);

            if (resultCount == 0)
            {
                throw new ProtocolEncodingException("The DCE/RPC bind acknowledgment does not contain any presentation-context results.");
            }

            bindAck.ResultCode = reader.ReadUInt16();
            bindAck.ReasonCode = reader.ReadUInt16();
            bindAck.TransferSyntaxId = reader.ReadGuid();
            bindAck.TransferSyntaxVersionMajor = reader.ReadUInt16();
            bindAck.TransferSyntaxVersionMinor = reader.ReadUInt16();
            return bindAck;
        }

        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte(0x05);
            writer.WriteByte(0x00);
            writer.WriteByte((byte)DceRpcPacketType.BindAck);
            writer.WriteByte((byte)(DceRpcPacketFlags.FirstFragment | DceRpcPacketFlags.LastFragment));
            writer.WriteByte(0x10);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt32(CallId);
            writer.WriteUInt16(MaximumTransmitFragment);
            writer.WriteUInt16(MaximumReceiveFragment);
            writer.WriteUInt32(AssociationGroupId);
            writer.WriteUInt16(0);
            DceRpcEncoding.PadWriterAlignment(writer, 4);
            writer.WriteByte(0x01);
            writer.WriteByte(0x00);
            writer.WriteUInt16(0);
            writer.WriteUInt16(ResultCode);
            writer.WriteUInt16(ReasonCode);
            writer.WriteGuid(TransferSyntaxId);
            writer.WriteUInt16(TransferSyntaxVersionMajor);
            writer.WriteUInt16(TransferSyntaxVersionMinor);
            byte[] packet = writer.ToArray();
            DceRpcEncoding.FinalizePacket(packet);
            return packet;
        }

        public void EnsureAccepted()
        {
            if (ResultCode != 0)
            {
                throw new ProtocolEncodingException(
                    "The DCE/RPC bind acknowledgment rejected the SRVSVC presentation context with result code " +
                    ResultCode +
                    " and reason code " +
                    ReasonCode +
                    '.');
            }
        }
    }

    internal sealed class DceRpcRequestPdu
    {
        public uint CallId { get; set; } = 1;

        public ushort ContextId { get; set; } = DceRpcConstants.SrvsvcContextId;

        public ushort OperationNumber { get; set; }

        public byte[] StubData { get; set; } = Array.Empty<byte>();

        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte(0x05);
            writer.WriteByte(0x00);
            writer.WriteByte((byte)DceRpcPacketType.Request);
            writer.WriteByte((byte)(DceRpcPacketFlags.FirstFragment | DceRpcPacketFlags.LastFragment));
            writer.WriteByte(0x10);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt32(CallId);
            writer.WriteUInt32((uint)StubData.Length);
            writer.WriteUInt16(ContextId);
            writer.WriteUInt16(OperationNumber);
            writer.WriteBytes(StubData);
            byte[] packet = writer.ToArray();
            DceRpcEncoding.FinalizePacket(packet);
            return packet;
        }

        public static DceRpcRequestPdu ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 24)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete DCE/RPC request.");
            }

            LittleEndianReader headerReader = new LittleEndianReader(buffer);
            DceRpcEncoding.ValidateCommonHeader(headerReader, buffer.Length, out DceRpcPacketType packetType, out _, out ushort fragmentLength, out uint callId);

            if (packetType != DceRpcPacketType.Request)
            {
                throw new ProtocolEncodingException("The DCE/RPC packet type is " + packetType + " instead of the expected Request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(16, fragmentLength - 16));
            uint allocationHint = reader.ReadUInt32();
            DceRpcRequestPdu request = new DceRpcRequestPdu
            {
                CallId = callId,
                ContextId = reader.ReadUInt16(),
                OperationNumber = reader.ReadUInt16(),
                StubData = reader.ReadBytes(reader.RemainingBytes)
            };

            if (allocationHint != request.StubData.Length)
            {
                throw new ProtocolEncodingException("The DCE/RPC request allocation hint does not match the bounded payload length.");
            }

            return request;
        }
    }

    internal sealed class DceRpcResponsePdu
    {
        public uint CallId { get; set; }

        public ushort ContextId { get; set; }

        public byte[] StubData { get; set; } = Array.Empty<byte>();

        public static DceRpcResponsePdu ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 24)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete DCE/RPC response.");
            }

            List<byte> stubBytes = new List<byte>();
            int offset = 0;
            uint? expectedCallId = null;
            ushort? expectedContextId = null;

            while (offset < buffer.Length)
            {
                ReadOnlyMemory<byte> remaining = buffer.Slice(offset);
                LittleEndianReader headerReader = new LittleEndianReader(remaining);
                DceRpcEncoding.ValidateCommonHeader(headerReader, remaining.Length, out DceRpcPacketType packetType, out DceRpcPacketFlags flags, out ushort fragmentLength, out uint callId);

                if (fragmentLength < 24 || fragmentLength > remaining.Length)
                {
                    throw new ProtocolEncodingException("The DCE/RPC response fragment length is invalid.");
                }

                if (packetType == DceRpcPacketType.Fault)
                {
                    LittleEndianReader faultReader = new LittleEndianReader(remaining.Slice(16, fragmentLength - 16));
                    uint allocationHint = faultReader.ReadUInt32();
                    ushort faultContextId = faultReader.ReadUInt16();
                    byte cancelCount = faultReader.ReadByte();
                    _ = faultReader.ReadByte();
                    uint status = faultReader.ReadUInt32();
                    throw new ProtocolEncodingException(
                        "The server returned a DCE/RPC fault response instead of the expected SRVSVC reply. " +
                        "Status=0x" +
                        status.ToString("X8", System.Globalization.CultureInfo.InvariantCulture) +
                        ", ContextId=" +
                        faultContextId.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                        ", CancelCount=" +
                        cancelCount.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                        ", AllocationHint=" +
                        allocationHint.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                        '.');
                }

                if (packetType != DceRpcPacketType.Response)
                {
                    throw new ProtocolEncodingException("The server returned an unexpected DCE/RPC packet type " + packetType + '.');
                }

                if (expectedCallId == null)
                {
                    expectedCallId = callId;
                }
                else if (expectedCallId.Value != callId)
                {
                    throw new ProtocolEncodingException("The DCE/RPC response fragments do not share a single call identifier.");
                }

                LittleEndianReader reader = new LittleEndianReader(remaining.Slice(16, fragmentLength - 16));
                _ = reader.ReadUInt32();
                ushort contextId = reader.ReadUInt16();
                _ = reader.ReadByte();
                _ = reader.ReadByte();

                if (expectedContextId == null)
                {
                    expectedContextId = contextId;
                }
                else if (expectedContextId.Value != contextId)
                {
                    throw new ProtocolEncodingException("The DCE/RPC response fragments do not share a single presentation context identifier.");
                }

                stubBytes.AddRange(reader.ReadBytes(reader.RemainingBytes));
                offset += fragmentLength;

                if ((flags & DceRpcPacketFlags.LastFragment) != 0)
                {
                    break;
                }
            }

            if (offset != buffer.Length)
            {
                throw new ProtocolEncodingException("The DCE/RPC response contains trailing bytes after the terminal fragment.");
            }

            return new DceRpcResponsePdu
            {
                CallId = expectedCallId ?? 0,
                ContextId = expectedContextId ?? 0,
                StubData = stubBytes.ToArray()
            };
        }

        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte(0x05);
            writer.WriteByte(0x00);
            writer.WriteByte((byte)DceRpcPacketType.Response);
            writer.WriteByte((byte)(DceRpcPacketFlags.FirstFragment | DceRpcPacketFlags.LastFragment));
            writer.WriteByte(0x10);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteUInt16(0);
            writer.WriteUInt16(0);
            writer.WriteUInt32(CallId);
            writer.WriteUInt32((uint)StubData.Length);
            writer.WriteUInt16(ContextId);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
            writer.WriteBytes(StubData);
            byte[] packet = writer.ToArray();
            DceRpcEncoding.FinalizePacket(packet);
            return packet;
        }
    }

    internal static class DceRpcEncoding
    {
        internal static void WriteUniquePointer(LittleEndianWriter writer, uint referentId)
        {
            writer.WriteUInt32(referentId);
        }

        internal static void WriteNdrUtf16String(LittleEndianWriter writer, string value)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer), "Writer cannot be null.");
            }

            string normalized = value ?? throw new ArgumentNullException(nameof(value), "Value cannot be null.");
            string terminated = normalized.EndsWith("\0", StringComparison.Ordinal) ? normalized : normalized + '\0';
            ushort[] codeUnits = new ushort[terminated.Length];

            for (int index = 0; index < terminated.Length; index++)
            {
                codeUnits[index] = terminated[index];
            }

            writer.WriteUInt32((uint)codeUnits.Length);
            writer.WriteUInt32(0);
            writer.WriteUInt32((uint)codeUnits.Length);

            for (int index = 0; index < codeUnits.Length; index++)
            {
                writer.WriteUInt16(codeUnits[index]);
            }

            PadWriterAlignment(writer, 4);
        }

        internal static string ReadNdrUtf16String(LittleEndianReader reader)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader), "Reader cannot be null.");
            }

            uint maximumCount = reader.ReadUInt32();
            uint offset = reader.ReadUInt32();
            uint actualCount = reader.ReadUInt32();

            if (offset != 0)
            {
                throw new ProtocolEncodingException("The DCE/RPC UTF-16 string contains a non-zero offset that is outside the bounded OpenCIFS RPC slice.");
            }

            if (actualCount == 0 || actualCount > maximumCount)
            {
                throw new ProtocolEncodingException("The DCE/RPC UTF-16 string counts are invalid.");
            }

            int charCount = checked((int)actualCount);
            char[] characters = new char[charCount];

            for (int index = 0; index < charCount; index++)
            {
                characters[index] = (char)reader.ReadUInt16();
            }

            if (characters[charCount - 1] != '\0')
            {
                throw new ProtocolEncodingException("The DCE/RPC UTF-16 string is not null terminated.");
            }

            SkipReaderAlignment(reader, 4);
            return new string(characters, 0, charCount - 1);
        }

        internal static void PadWriterAlignment(LittleEndianWriter writer, int alignment)
        {
            if (writer == null)
            {
                throw new ArgumentNullException(nameof(writer), "Writer cannot be null.");
            }

            if (alignment <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(alignment), "Alignment must be positive.");
            }

            while ((writer.Length % alignment) != 0)
            {
                writer.WriteByte(0x00);
            }
        }

        internal static void SkipReaderAlignment(LittleEndianReader reader, int alignment)
        {
            if (reader == null)
            {
                throw new ArgumentNullException(nameof(reader), "Reader cannot be null.");
            }

            if (alignment <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(alignment), "Alignment must be positive.");
            }

            int remainder = reader.Position % alignment;
            if (remainder == 0)
            {
                return;
            }

            reader.Skip(alignment - remainder);
        }

        internal static void ValidateCommonHeader(
            LittleEndianReader headerReader,
            DceRpcPacketType expectedPacketType,
            int availableLength,
            out ushort fragmentLength)
        {
            ValidateCommonHeader(headerReader, availableLength, out DceRpcPacketType packetType, out _, out fragmentLength, out _);

            if (packetType != expectedPacketType)
            {
                throw new ProtocolEncodingException("The DCE/RPC packet type is " + packetType + " instead of the expected " + expectedPacketType + '.');
            }
        }

        internal static void ValidateCommonHeader(
            LittleEndianReader headerReader,
            int availableLength,
            out DceRpcPacketType packetType,
            out DceRpcPacketFlags flags,
            out ushort fragmentLength,
            out uint callId)
        {
            byte majorVersion = headerReader.ReadByte();
            byte minorVersion = headerReader.ReadByte();
            packetType = (DceRpcPacketType)headerReader.ReadByte();
            flags = (DceRpcPacketFlags)headerReader.ReadByte();

            if (majorVersion != 0x05 || minorVersion != 0x00)
            {
                throw new ProtocolEncodingException("The DCE/RPC packet uses an unsupported major or minor version.");
            }

            byte dataRepresentation = headerReader.ReadByte();
            headerReader.Skip(3);

            if (dataRepresentation != 0x10)
            {
                throw new ProtocolEncodingException("The bounded OpenCIFS RPC slice only supports little-endian DCE/RPC packets.");
            }

            fragmentLength = headerReader.ReadUInt16();
            _ = headerReader.ReadUInt16();
            callId = headerReader.ReadUInt32();

            if (fragmentLength < 16 || fragmentLength > availableLength)
            {
                throw new ProtocolEncodingException("The DCE/RPC packet fragment length is invalid.");
            }
        }

        internal static void FinalizePacket(byte[] packet)
        {
            if (packet == null)
            {
                throw new ArgumentNullException(nameof(packet), "Packet cannot be null.");
            }

            if (packet.Length > UInt16.MaxValue)
            {
                throw new ProtocolEncodingException("The DCE/RPC packet exceeds the bounded 16-bit fragment length range.");
            }

            packet[8] = (byte)(packet.Length & 0xFF);
            packet[9] = (byte)((packet.Length >> 8) & 0xFF);
        }
    }
}
