namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Encodes and decodes SMB2 create-context buffers.
    /// </summary>
    public static class Smb2CreateContextCodec
    {
        private const int FixedHeaderLength = 16;

        /// <summary>
        /// Encode create contexts into a CREATE request or response buffer.
        /// </summary>
        /// <param name="contexts">Contexts to encode.</param>
        /// <returns>Encoded create-context buffer.</returns>
        public static byte[] Encode(IReadOnlyList<Smb2CreateContext> contexts)
        {
            if (contexts == null)
            {
                throw new ArgumentNullException(nameof(contexts), "Contexts cannot be null.");
            }

            if (contexts.Count == 0)
            {
                return Array.Empty<byte>();
            }

            byte[][] contextBuffers = new byte[contexts.Count][];
            int totalLength = 0;

            for (int index = 0; index < contexts.Count; index++)
            {
                contextBuffers[index] = EncodeContext(contexts[index], hasNextContext: index < contexts.Count - 1);
                totalLength += contextBuffers[index].Length;
            }

            byte[] buffer = new byte[totalLength];
            int offset = 0;

            for (int index = 0; index < contextBuffers.Length; index++)
            {
                Buffer.BlockCopy(contextBuffers[index], 0, buffer, offset, contextBuffers[index].Length);
                offset += contextBuffers[index].Length;
            }

            return buffer;
        }

        /// <summary>
        /// Decode a CREATE request or response create-context buffer.
        /// </summary>
        /// <param name="buffer">Create-context bytes.</param>
        /// <returns>Decoded contexts.</returns>
        public static Smb2CreateContext[] Decode(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length == 0)
            {
                return Array.Empty<Smb2CreateContext>();
            }

            List<Smb2CreateContext> contexts = new List<Smb2CreateContext>();
            int offset = 0;

            while (offset < buffer.Length)
            {
                if (buffer.Length - offset < FixedHeaderLength)
                {
                    throw new ProtocolEncodingException("The SMB2 create-context buffer does not contain a complete context header.");
                }

                ReadOnlyMemory<byte> contextBuffer = buffer.Slice(offset);
                LittleEndianReader reader = new LittleEndianReader(contextBuffer);
                uint next = reader.ReadUInt32();
                ushort nameOffset = reader.ReadUInt16();
                ushort nameLength = reader.ReadUInt16();
                reader.Skip(2);
                ushort dataOffset = reader.ReadUInt16();
                uint dataLength = reader.ReadUInt32();

                if (nameLength < 4)
                {
                    throw new ProtocolEncodingException("The SMB2 create-context name must be at least four bytes long.");
                }

                if (nameOffset < FixedHeaderLength || (nameOffset % 8) != 0)
                {
                    throw new ProtocolEncodingException("The SMB2 create-context name offset is invalid.");
                }

                if (dataLength > Int32.MaxValue)
                {
                    throw new ProtocolEncodingException("The SMB2 create-context data length exceeds the supported maximum.");
                }

                int nameOffsetValue = nameOffset;
                int nameLengthValue = nameLength;
                int dataOffsetValue = dataOffset;
                int dataLengthValue = checked((int)dataLength);

                if (nameOffsetValue + nameLengthValue > contextBuffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB2 create-context name exceeds the available payload.");
                }

                if (dataLengthValue != 0)
                {
                    if (dataOffsetValue < FixedHeaderLength || (dataOffsetValue % 8) != 0)
                    {
                        throw new ProtocolEncodingException("The SMB2 create-context data offset is invalid.");
                    }

                    if (dataOffsetValue + dataLengthValue > contextBuffer.Length)
                    {
                        throw new ProtocolEncodingException("The SMB2 create-context data exceeds the available payload.");
                    }
                }

                int minimumContextLength = Math.Max(
                    nameOffsetValue + nameLengthValue,
                    dataLengthValue == 0 ? 0 : dataOffsetValue + dataLengthValue);
                minimumContextLength = Math.Max(minimumContextLength, FixedHeaderLength);
                int alignedContextLength = Math.Max(
                    AlignToEight(nameOffsetValue + nameLengthValue),
                    dataLengthValue == 0 ? 0 : AlignToEight(dataOffsetValue + dataLengthValue));
                alignedContextLength = Math.Max(alignedContextLength, FixedHeaderLength);

                if (minimumContextLength > contextBuffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB2 create-context payload is truncated.");
                }

                int consumedLength = next == 0
                    ? (alignedContextLength <= contextBuffer.Length ? alignedContextLength : minimumContextLength)
                    : checked((int)next);

                if (next != 0)
                {
                    if ((consumedLength % 8) != 0 || consumedLength < alignedContextLength)
                    {
                        throw new ProtocolEncodingException("The SMB2 create-context Next offset is invalid.");
                    }

                    if (offset + consumedLength > buffer.Length)
                    {
                        throw new ProtocolEncodingException("The SMB2 create-context Next offset exceeds the available buffer.");
                    }
                }

                contexts.Add(new Smb2CreateContext
                {
                    Name = contextBuffer.Slice(nameOffsetValue, nameLengthValue).ToArray(),
                    Data = dataLengthValue == 0
                        ? Array.Empty<byte>()
                        : contextBuffer.Slice(dataOffsetValue, dataLengthValue).ToArray()
                });

                offset += consumedLength;

                if (next == 0)
                {
                    if (offset != buffer.Length)
                    {
                        if (!ContainsOnlyZeroPadding(buffer.Slice(offset)))
                        {
                            throw new ProtocolEncodingException("The SMB2 create-context buffer contains trailing bytes after the final context.");
                        }
                    }

                    break;
                }
            }

            return contexts.ToArray();
        }

        private static byte[] EncodeContext(Smb2CreateContext context, bool hasNextContext)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }

            byte[] name = context.Name;
            byte[] data = context.Data;

            if (name.Length < 4)
            {
                throw new ProtocolValidationException("The SMB2 create-context name must be at least four bytes long.", nameof(context));
            }

            int nameOffset = FixedHeaderLength;
            int dataOffset = data.Length == 0
                ? 0
                : AlignToEight(nameOffset + name.Length);
            int contextLength = Math.Max(
                AlignToEight(nameOffset + name.Length),
                data.Length == 0 ? 0 : AlignToEight(dataOffset + data.Length));
            contextLength = Math.Max(contextLength, FixedHeaderLength);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(hasNextContext ? checked((uint)contextLength) : 0U);
            writer.WriteUInt16((ushort)nameOffset);
            writer.WriteUInt16((ushort)name.Length);
            writer.WriteUInt16(0);
            writer.WriteUInt16((ushort)dataOffset);
            writer.WriteUInt32((uint)data.Length);
            writer.WriteBytes(name);

            while (writer.Length < dataOffset)
            {
                writer.WriteByte(0);
            }

            writer.WriteBytes(data);

            while (writer.Length < contextLength)
            {
                writer.WriteByte(0);
            }

            return writer.ToArray();
        }

        private static int AlignToEight(int value)
        {
            int remainder = value % 8;
            return remainder == 0 ? value : value + (8 - remainder);
        }

        private static bool ContainsOnlyZeroPadding(ReadOnlyMemory<byte> buffer)
        {
            ReadOnlySpan<byte> span = buffer.Span;

            for (int index = 0; index < span.Length; index++)
            {
                if (span[index] != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
