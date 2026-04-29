namespace OpenCIFS.Security
{
    using System;
    using System.Buffers.Binary;
    using System.Text;
    using OpenCIFS.Protocol;

    internal readonly struct NtlmFieldDescriptor
    {
        public NtlmFieldDescriptor(ushort length, uint offset)
        {
            Length = length;
            Offset = offset;
        }

        public ushort Length { get; }

        public uint Offset { get; }
    }

    internal static class NtlmMessageUtilities
    {
        private static readonly byte[] Signature = Encoding.ASCII.GetBytes("NTLMSSP\0");

        internal static bool HasSignature(ReadOnlySpan<byte> buffer)
        {
            return buffer.Length >= Signature.Length &&
                buffer.Slice(0, Signature.Length).SequenceEqual(Signature);
        }

        internal static void ValidateMessage(ReadOnlyMemory<byte> buffer, NtlmMessageType expectedType, int minimumLength)
        {
            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete NTLM message.");
            }

            if (!HasSignature(buffer.Span))
            {
                throw new ProtocolEncodingException("The buffer does not start with the NTLMSSP signature.");
            }

            uint actualType = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Span.Slice(8, 4));

            if (actualType != (uint)expectedType)
            {
                throw new ProtocolEncodingException("The buffer does not contain the expected NTLM message type.");
            }
        }

        internal static NtlmFieldDescriptor ReadFieldDescriptor(ReadOnlySpan<byte> buffer, int offset)
        {
            if (offset < 0 || offset + 8 > buffer.Length)
            {
                throw new ProtocolEncodingException("The NTLM security-buffer descriptor is out of range.");
            }

            ushort length = BinaryPrimitives.ReadUInt16LittleEndian(buffer.Slice(offset, 2));
            uint payloadOffset = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(offset + 4, 4));
            return new NtlmFieldDescriptor(length, payloadOffset);
        }

        internal static byte[] ReadPayload(ReadOnlyMemory<byte> buffer, NtlmFieldDescriptor descriptor)
        {
            if (descriptor.Length == 0)
            {
                return Array.Empty<byte>();
            }

            if (descriptor.Offset > int.MaxValue || descriptor.Offset + descriptor.Length > buffer.Length)
            {
                throw new ProtocolEncodingException("An NTLM security-buffer descriptor points beyond the message boundary.");
            }

            return buffer.Slice((int)descriptor.Offset, descriptor.Length).ToArray();
        }

        internal static string ReadTextPayload(ReadOnlyMemory<byte> buffer, NtlmFieldDescriptor descriptor, Encoding encoding)
        {
            byte[] bytes = ReadPayload(buffer, descriptor);
            return bytes.Length == 0 ? string.Empty : encoding.GetString(bytes);
        }

        internal static void WriteFieldDescriptor(LittleEndianWriter writer, int length, uint offset)
        {
            if (length < 0 || length > ushort.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "The NTLM security-buffer length must fit in 16 bits.");
            }

            writer.WriteUInt16((ushort)length);
            writer.WriteUInt16((ushort)length);
            writer.WriteUInt32(offset);
        }

        internal static int GetPayloadOffset(ReadOnlySpan<byte> buffer, params int[] fieldOffsets)
        {
            int payloadOffset = buffer.Length;

            for (int index = 0; index < fieldOffsets.Length; index++)
            {
                int fieldOffset = fieldOffsets[index];

                if (fieldOffset < 0 || fieldOffset + 8 > buffer.Length)
                {
                    throw new ProtocolEncodingException("The NTLM message contains an out-of-range security-buffer descriptor.");
                }

                uint candidate = BinaryPrimitives.ReadUInt32LittleEndian(buffer.Slice(fieldOffset + 4, 4));

                if (candidate != 0 && candidate < payloadOffset)
                {
                    payloadOffset = checked((int)candidate);
                }
            }

            return payloadOffset;
        }

        internal static Encoding GetTextEncoding(NtlmNegotiateFlags flags)
        {
            return (flags & NtlmNegotiateFlags.Unicode) != 0 ? Encoding.Unicode : Encoding.ASCII;
        }
    }
}
