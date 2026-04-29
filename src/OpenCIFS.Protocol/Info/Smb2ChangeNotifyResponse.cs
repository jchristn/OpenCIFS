namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 CHANGE_NOTIFY response payload.
    /// </summary>
    public sealed class Smb2ChangeNotifyResponse
    {
        private const ushort StructureSize = 9;
        private const ushort FixedBodyLength = 8;

        /// <summary>
        /// Encoded FILE_NOTIFY_INFORMATION buffer.
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
        /// Serialize the response body to wire format.
        /// </summary>
        /// <returns>Response-body bytes.</returns>
        public byte[] ToByteArray()
        {
            ushort outputBufferOffset = OutputBuffer.Length == 0
                ? (ushort)0
                : (ushort)(ProtocolConstants.Smb2HeaderLength + FixedBodyLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(outputBufferOffset);
            writer.WriteUInt32((uint)OutputBuffer.Length);
            writer.WriteBytes(OutputBuffer);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the response body from wire format.
        /// </summary>
        /// <param name="buffer">Response-body bytes.</param>
        /// <returns>Parsed response.</returns>
        public static Smb2ChangeNotifyResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 CHANGE_NOTIFY response.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response structure size must be 9 bytes.");
            }

            ushort outputBufferOffset = reader.ReadUInt16();
            uint outputBufferLength = reader.ReadUInt32();

            if (outputBufferLength == 0)
            {
                if (reader.RemainingBytes != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response contains trailing bytes without an output-buffer length.");
                }

                return new Smb2ChangeNotifyResponse
                {
                    OutputBuffer = Array.Empty<byte>()
                };
            }

            if (outputBufferLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response output buffer exceeds the supported maximum.");
            }

            int relativeOutputBufferOffset = outputBufferOffset - ProtocolConstants.Smb2HeaderLength;
            int outputBufferLengthValue = checked((int)outputBufferLength);

            if (relativeOutputBufferOffset < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response output-buffer offset is invalid.");
            }

            if (relativeOutputBufferOffset + outputBufferLengthValue > buffer.Length)
            {
                throw new ProtocolEncodingException("The SMB2 CHANGE_NOTIFY response output buffer exceeds the available payload.");
            }

            return new Smb2ChangeNotifyResponse
            {
                OutputBuffer = buffer.Slice(relativeOutputBufferOffset, outputBufferLengthValue).ToArray()
            };
        }

        private byte[] _OutputBuffer = Array.Empty<byte>();
    }
}
