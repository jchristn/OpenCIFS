namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// NetBIOS session-service NEGATIVE_SESSION_RESPONSE PDU per RFC 1002 section 4.3.4.
    /// </summary>
    /// <remarks>
    /// Returned by a listener that refuses a SESSION_REQUEST. The payload is a single byte
    /// carrying one of the well-known error codes exposed by the <see cref="NetBiosNegativeSessionResponseErrorCode" />
    /// enum. The session-service header carries <see cref="NetBiosSessionMessageType.NegativeSessionResponse" />
    /// with Length=1.
    /// </remarks>
    public sealed class NetBiosNegativeSessionResponse
    {
        /// <summary>
        /// Total payload length carried after the session-service header, in bytes.
        /// </summary>
        public const int PayloadLength = 1;

        /// <summary>
        /// Error code conveyed by the response payload.
        /// </summary>
        public NetBiosNegativeSessionResponseErrorCode ErrorCode { get; set; } = NetBiosNegativeSessionResponseErrorCode.UnspecifiedError;

        /// <summary>
        /// Serialize the NEGATIVE_SESSION_RESPONSE PDU to its full wire form.
        /// </summary>
        /// <returns>Wire bytes.</returns>
        public byte[] ToByteArray()
        {
            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
            {
                MessageType = NetBiosSessionMessageType.NegativeSessionResponse,
                Length = PayloadLength
            };

            byte[] headerBytes = header.ToByteArray();
            byte[] result = new byte[NetBiosSessionServiceHeader.Size + PayloadLength];
            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
            result[NetBiosSessionServiceHeader.Size] = (byte)ErrorCode;
            return result;
        }

        /// <summary>
        /// Parse a NEGATIVE_SESSION_RESPONSE PDU from its full wire form.
        /// </summary>
        /// <param name="buffer">Wire bytes including the 4-byte session-service header.</param>
        /// <returns>Parsed PDU.</returns>
        public static NetBiosNegativeSessionResponse ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < NetBiosSessionServiceHeader.Size + PayloadLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete NetBIOS NEGATIVE_SESSION_RESPONSE PDU.");
            }

            NetBiosSessionServiceHeader header = NetBiosSessionServiceHeader.ReadFrom(buffer.Slice(0, NetBiosSessionServiceHeader.Size));

            if (header.MessageType != NetBiosSessionMessageType.NegativeSessionResponse)
            {
                throw new ProtocolEncodingException("The NetBIOS PDU does not carry a NEGATIVE_SESSION_RESPONSE message type.");
            }

            if (header.Length != PayloadLength)
            {
                throw new ProtocolEncodingException("The NetBIOS NEGATIVE_SESSION_RESPONSE length must be 1 byte.");
            }

            byte errorCode = buffer.Span[NetBiosSessionServiceHeader.Size];

            return new NetBiosNegativeSessionResponse
            {
                ErrorCode = (NetBiosNegativeSessionResponseErrorCode)errorCode
            };
        }
    }
}
