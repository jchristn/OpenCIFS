namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// NetBIOS session service header.
    /// </summary>
    public sealed class NetBiosSessionServiceHeader
    {
        /// <summary>
        /// NetBIOS session service header size in bytes.
        /// </summary>
        public const int Size = 4;

        /// <summary>
        /// Session message type.
        /// </summary>
        public NetBiosSessionMessageType MessageType { get; set; } = NetBiosSessionMessageType.SessionMessage;

        /// <summary>
        /// Payload length in bytes.
        /// Minimum value: <c>0</c>.
        /// Maximum value: <c>16777215</c>.
        /// </summary>
        public int Length
        {
            get
            {
                return _Length;
            }
            set
            {
                if (value < 0 || value > 0x00FFFFFF)
                {
                    throw new ArgumentOutOfRangeException(nameof(Length), "NetBIOS session service lengths must fit within 24 bits.");
                }

                _Length = value;
            }
        }

        /// <summary>
        /// Serialize the header.
        /// </summary>
        /// <returns>Header bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte((byte)MessageType);
            writer.WriteUInt24BigEndian((uint)Length);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the header from a binary buffer.
        /// </summary>
        /// <param name="buffer">Header bytes.</param>
        /// <returns>Parsed header.</returns>
        public static NetBiosSessionServiceHeader ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < Size)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete NetBIOS session service header.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
            {
                MessageType = (NetBiosSessionMessageType)reader.ReadByte(),
                Length = checked((int)reader.ReadUInt24BigEndian())
            };

            return header;
        }

        private int _Length = 0;
    }
}
