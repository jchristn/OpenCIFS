namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Direct TCP transport header for SMB frame payloads.
    /// </summary>
    public sealed class DirectTcpFrameHeader
    {
        /// <summary>
        /// Direct TCP header size in bytes.
        /// </summary>
        public const int Size = 4;

        /// <summary>
        /// Payload length in bytes.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>2147483647</c>.
        /// </summary>
        public int Length
        {
            get
            {
                return _Length;
            }
            set
            {
                if (value <= 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(Length), "Direct TCP frame lengths must be positive.");
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
            writer.WriteUInt32BigEndian((uint)Length);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the header from a binary buffer.
        /// </summary>
        /// <param name="buffer">Header bytes.</param>
        /// <returns>Parsed header.</returns>
        public static DirectTcpFrameHeader ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < Size)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete Direct TCP frame header.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            DirectTcpFrameHeader header = new DirectTcpFrameHeader
            {
                Length = checked((int)reader.ReadUInt32BigEndian())
            };

            return header;
        }

        private int _Length = 1;
    }
}
