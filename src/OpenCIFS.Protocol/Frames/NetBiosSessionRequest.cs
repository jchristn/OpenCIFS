namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// NetBIOS session-service SESSION_REQUEST PDU per RFC 1002 section 4.3.2.
    /// </summary>
    /// <remarks>
    /// Sent by the calling node to establish a session with the listener identified by
    /// <see cref="CalledName" />. The payload is the 34-byte called-name encoding immediately
    /// followed by the 34-byte calling-name encoding (68 bytes total). The session-service
    /// header carries <see cref="NetBiosSessionMessageType.SessionRequest" /> with Length=68.
    /// </remarks>
    public sealed class NetBiosSessionRequest
    {
        /// <summary>
        /// Total payload length carried after the session-service header, in bytes.
        /// </summary>
        public const int PayloadLength = NetBiosEncodedName.WireLength * 2;

        /// <summary>
        /// Encoded called (target) NetBIOS name.
        /// </summary>
        public NetBiosEncodedName CalledName
        {
            get
            {
                return _CalledName;
            }
            set
            {
                _CalledName = value ?? throw new ArgumentNullException(nameof(CalledName), "CalledName cannot be null.");
            }
        }

        /// <summary>
        /// Encoded calling (originator) NetBIOS name.
        /// </summary>
        public NetBiosEncodedName CallingName
        {
            get
            {
                return _CallingName;
            }
            set
            {
                _CallingName = value ?? throw new ArgumentNullException(nameof(CallingName), "CallingName cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the SESSION_REQUEST PDU to its full wire form (4-byte header + 68-byte payload).
        /// </summary>
        /// <returns>Wire bytes.</returns>
        public byte[] ToByteArray()
        {
            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
            {
                MessageType = NetBiosSessionMessageType.SessionRequest,
                Length = PayloadLength
            };

            byte[] headerBytes = header.ToByteArray();
            byte[] calledBytes = CalledName.ToByteArray();
            byte[] callingBytes = CallingName.ToByteArray();
            byte[] result = new byte[NetBiosSessionServiceHeader.Size + PayloadLength];

            Buffer.BlockCopy(headerBytes, 0, result, 0, headerBytes.Length);
            Buffer.BlockCopy(calledBytes, 0, result, NetBiosSessionServiceHeader.Size, calledBytes.Length);
            Buffer.BlockCopy(callingBytes, 0, result, NetBiosSessionServiceHeader.Size + calledBytes.Length, callingBytes.Length);
            return result;
        }

        /// <summary>
        /// Parse a SESSION_REQUEST PDU from its full wire form.
        /// </summary>
        /// <param name="buffer">Wire bytes including the 4-byte session-service header.</param>
        /// <returns>Parsed PDU.</returns>
        public static NetBiosSessionRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < NetBiosSessionServiceHeader.Size + PayloadLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete NetBIOS SESSION_REQUEST PDU.");
            }

            NetBiosSessionServiceHeader header = NetBiosSessionServiceHeader.ReadFrom(buffer.Slice(0, NetBiosSessionServiceHeader.Size));

            if (header.MessageType != NetBiosSessionMessageType.SessionRequest)
            {
                throw new ProtocolEncodingException("The NetBIOS PDU does not carry a SESSION_REQUEST message type.");
            }

            if (header.Length != PayloadLength)
            {
                throw new ProtocolEncodingException("The NetBIOS SESSION_REQUEST length must be 68 bytes.");
            }

            int payloadOffset = NetBiosSessionServiceHeader.Size;
            NetBiosEncodedName calledName = NetBiosEncodedName.ReadFrom(buffer.Slice(payloadOffset, NetBiosEncodedName.WireLength));
            NetBiosEncodedName callingName = NetBiosEncodedName.ReadFrom(buffer.Slice(payloadOffset + NetBiosEncodedName.WireLength, NetBiosEncodedName.WireLength));

            return new NetBiosSessionRequest
            {
                CalledName = calledName,
                CallingName = callingName
            };
        }

        private NetBiosEncodedName _CalledName = new NetBiosEncodedName();
        private NetBiosEncodedName _CallingName = new NetBiosEncodedName();
    }
}
