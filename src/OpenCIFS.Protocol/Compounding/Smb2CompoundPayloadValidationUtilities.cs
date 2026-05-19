namespace OpenCIFS.Protocol
{
    using System;

    internal static class Smb2CompoundPayloadValidationUtilities
    {
        internal static int GetFixedPayloadLength(ReadOnlyMemory<byte> payload, int expectedLength, string incompleteMessage)
        {
            if (payload.Length < expectedLength)
            {
                throw new ProtocolEncodingException(incompleteMessage);
            }

            return expectedLength;
        }

        internal static int GetVariableLengthPayloadEnd(int payloadLength, int fixedBodyLength, int relativeOffset, int dataLength, string invalidOffsetMessage, string exceedsPayloadMessage)
        {
            if (relativeOffset < fixedBodyLength)
            {
                throw new ProtocolEncodingException(invalidOffsetMessage);
            }

            int endOffset = checked(relativeOffset + dataLength);

            if (endOffset > payloadLength)
            {
                throw new ProtocolEncodingException(exceedsPayloadMessage);
            }

            return endOffset;
        }

        internal static ushort ReadStructureSize(ReadOnlyMemory<byte> payload, string truncatedMessage)
        {
            if (payload.Length < 2)
            {
                throw new ProtocolEncodingException(truncatedMessage);
            }

            LittleEndianReader reader = new LittleEndianReader(payload);
            return reader.ReadUInt16();
        }

        internal static void EnsureTrailingPaddingIsZero(ReadOnlyMemory<byte> payload, int contentLength, string errorMessage)
        {
            if (contentLength < 0 || contentLength > payload.Length)
            {
                throw new ProtocolEncodingException("The SMB2 compounded payload length is invalid.");
            }

            ReadOnlySpan<byte> trailingSpan = payload.Span.Slice(contentLength);

            for (int index = 0; index < trailingSpan.Length; index++)
            {
                if (trailingSpan[index] != 0)
                {
                    throw new ProtocolEncodingException(errorMessage);
                }
            }
        }
    }
}
