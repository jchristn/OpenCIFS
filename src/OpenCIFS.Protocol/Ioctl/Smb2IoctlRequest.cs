namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 IOCTL request payload.
    /// </summary>
    public sealed class Smb2IoctlRequest
    {
        private const ushort StructureSize = 57;
        private const ushort FixedBodyLength = 56;

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
        /// Maximum number of bytes the server may return in the response input buffer.
        /// </summary>
        public uint MaxInputResponse { get; set; }

        /// <summary>
        /// Maximum number of bytes the server may return in the response output buffer.
        /// </summary>
        public uint MaxOutputResponse { get; set; }

        /// <summary>
        /// IOCTL flags.
        /// </summary>
        public Smb2IoctlFlags Flags { get; set; } = Smb2IoctlFlags.IsFsctl;

        /// <summary>
        /// Optional input buffer bytes.
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
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Request-body bytes.</returns>
        public byte[] ToByteArray()
        {
            uint inputOffset = InputBuffer.Length == 0
                ? 0U
                : (uint)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(0);
            writer.WriteUInt32(CtlCode);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteUInt32(inputOffset);
            writer.WriteUInt32((uint)InputBuffer.Length);
            writer.WriteUInt32(MaxInputResponse);
            writer.WriteUInt32(0);
            writer.WriteUInt32(0);
            writer.WriteUInt32(MaxOutputResponse);
            writer.WriteUInt32((uint)Flags);
            writer.WriteUInt32(0);
            writer.WriteBytes(InputBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Request-body bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2IoctlRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 IOCTL request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request structure size must be 57 bytes.");
            }

            reader.Skip(2);

            Smb2IoctlRequest request = new Smb2IoctlRequest
            {
                CtlCode = reader.ReadUInt32(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64()
            };
            uint inputOffset = reader.ReadUInt32();
            uint inputCount = reader.ReadUInt32();
            request.MaxInputResponse = reader.ReadUInt32();
            reader.Skip(4);
            uint outputCount = reader.ReadUInt32();
            request.MaxOutputResponse = reader.ReadUInt32();
            request.Flags = (Smb2IoctlFlags)reader.ReadUInt32();
            reader.Skip(4);

            if (outputCount != 0)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request output-count field must remain zero.");
            }

            if (inputCount == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 IOCTL request contains trailing bytes without an input-buffer length.");
                }

                request.InputBuffer = Array.Empty<byte>();
                return request;
            }

            if (inputCount > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request input buffer exceeds the supported maximum.");
            }

            if ((inputOffset % 8) != 0)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request input-buffer offset must be aligned to 8 bytes.");
            }

            int relativeInputOffset = checked((int)inputOffset - ProtocolConstants.Smb2HeaderLength);
            int inputLength = checked((int)inputCount);

            if (relativeInputOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request input-buffer offset is invalid.");
            }

            if (relativeInputOffset + inputLength > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 IOCTL request input buffer exceeds the available payload.");
            }

            request.InputBuffer = buffer.Slice(relativeInputOffset, inputLength).ToArray();
            return request;
        }

        private byte[] _InputBuffer = Array.Empty<byte>();
    }
}
