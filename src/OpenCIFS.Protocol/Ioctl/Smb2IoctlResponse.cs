namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 IOCTL response payload.
    /// </summary>
    public sealed class Smb2IoctlResponse
    {
        private const ushort StructureSize = 49;
        private const ushort FixedBodyLength = 48;

        /// <summary>
        /// FSCTL or IOCTL control code.
        /// </summary>
        public uint CtlCode { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Optional input buffer returned in the response.
        /// </summary>
        public byte[] InputBuffer
        {
            get
            {
                return _InputBuffer;
            }
            set
            {
                _InputBuffer = value ?? throw new ArgumentNullException(nameof(InputBuffer), "InputBuffer cannot be null.");
            }
        }

        /// <summary>
        /// Optional output buffer returned in the response.
        /// </summary>
        public byte[] OutputBuffer
        {
            get
            {
                return _OutputBuffer;
            }
            set
            {
                _OutputBuffer = value ?? throw new ArgumentNullException(nameof(OutputBuffer), "OutputBuffer cannot be null.");
            }
        }

        /// <summary>
        /// Reserved flags field.
        /// </summary>
        public uint Flags { get; set; }

        /// <summary>
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            bool hasAnyBuffer = InputBuffer.Length != 0 || OutputBuffer.Length != 0;
            uint inputOffset = hasAnyBuffer
                ? (uint)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength)
                : 0U;
            int outputRelativeOffset = AlignTo8(FixedBodyLength + InputBuffer.Length);
            uint outputOffset = OutputBuffer.Length == 0
                ? 0U
                : (uint)(ProtocolConstants.Smb2HeaderLength + outputRelativeOffset);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(0);
            writer.WriteUInt32(CtlCode);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt32(inputOffset);
            writer.WriteUInt32((uint)InputBuffer.Length);
            writer.WriteUInt32(outputOffset);
            writer.WriteUInt32((uint)OutputBuffer.Length);
            writer.WriteUInt32(Flags);
            writer.WriteUInt32(0);
            writer.WriteBytes(InputBuffer);

            int paddingLength = OutputBuffer.Length == 0
                ? 0
                : outputRelativeOffset - (FixedBodyLength + InputBuffer.Length);

            if (paddingLength > 0)
            {
                writer.WriteBytes(new byte[paddingLength]);
            }

            writer.WriteBytes(OutputBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2IoctlResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 IOCTL response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL response structure size must be 49 bytes.");
            }

            reader.Skip(2);

            Smb2IoctlResponse response = new Smb2IoctlResponse
            {
                CtlCode = reader.ReadUInt32(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64()
            };
            uint inputOffset = reader.ReadUInt32();
            uint inputCount = reader.ReadUInt32();
            uint outputOffset = reader.ReadUInt32();
            uint outputCount = reader.ReadUInt32();
            response.Flags = reader.ReadUInt32();
            reader.Skip(4);

            if (inputCount > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL response input buffer exceeds the supported maximum.");
            }

            if (outputCount > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL response output buffer exceeds the supported maximum.");
            }

            if (inputCount == 0 && outputCount == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 IOCTL response contains trailing bytes without input or output buffers.");
                }

                response.InputBuffer = Array.Empty<byte>();
                response.OutputBuffer = Array.Empty<byte>();
                return response;
            }

            response.InputBuffer = ReadBuffer(
                buffer,
                inputOffset,
                inputCount,
                FixedBodyLength,
                "The SMB2 IOCTL response input-buffer offset must be aligned to 8 bytes.",
                "The SMB2 IOCTL response input-buffer offset is invalid.",
                "The SMB2 IOCTL response input buffer exceeds the available payload.");
            response.OutputBuffer = ReadBuffer(
                buffer,
                outputOffset,
                outputCount,
                FixedBodyLength,
                "The SMB2 IOCTL response output-buffer offset must be aligned to 8 bytes.",
                "The SMB2 IOCTL response output-buffer offset is invalid.",
                "The SMB2 IOCTL response output buffer exceeds the available payload.");
            return response;
        }

        private static byte[] ReadBuffer(
            ReadOnlyMemory<byte> buffer,
            uint offset,
            uint count,
            int fixedBodyLength,
            string alignmentMessage,
            string invalidOffsetMessage,
            string exceedsPayloadMessage)
        {
            if (count == 0)
            {
                return Array.Empty<byte>();
            }

            if ((offset % 8) != 0)
            {
                throw new ProtocolEncodingException(alignmentMessage);
            }

            int relativeOffset = checked((int)offset - ProtocolConstants.Smb2HeaderLength);
            int bufferLength = checked((int)count);

            if (relativeOffset < fixedBodyLength)
            {
                throw new ProtocolEncodingException(invalidOffsetMessage);
            }

            if (relativeOffset + bufferLength > buffer.Length)
            {
                throw new ProtocolEncodingException(exceedsPayloadMessage);
            }

            return buffer.Slice(relativeOffset, bufferLength).ToArray();
        }

        private static int AlignTo8(int value)
        {
            return (value + 7) & ~7;
        }

        private byte[] _InputBuffer = Array.Empty<byte>();
        private byte[] _OutputBuffer = Array.Empty<byte>();
    }
}
