namespace OpenCIFS.Protocol
{
    using System;
    using System.Buffers.Binary;

    /// <summary>
    /// Reads primitive values from a binary SMB/CIFS payload.
    /// </summary>
    public sealed class LittleEndianReader
    {
        /// <summary>
        /// Initialize the reader over a binary payload.
        /// </summary>
        /// <param name="buffer">Buffer to read.</param>
        public LittleEndianReader(ReadOnlyMemory<byte> buffer)
        {
            _Buffer = buffer;
        }

        /// <summary>
        /// Current cursor position in bytes.
        /// </summary>
        public int Position
        {
            get
            {
                return _Position;
            }
        }

        /// <summary>
        /// Remaining unread byte count.
        /// </summary>
        public int RemainingBytes
        {
            get
            {
                return _Buffer.Length - _Position;
            }
        }

        /// <summary>
        /// Read a single byte.
        /// </summary>
        /// <returns>Byte value.</returns>
        public byte ReadByte()
        {
            EnsureAvailable(1);
            byte value = _Buffer.Span[_Position];
            _Position += 1;
            return value;
        }

        /// <summary>
        /// Read a 16-bit unsigned integer in little-endian order.
        /// </summary>
        /// <returns>Unsigned 16-bit value.</returns>
        public ushort ReadUInt16()
        {
            EnsureAvailable(2);
            ushort value = BinaryPrimitives.ReadUInt16LittleEndian(_Buffer.Span.Slice(_Position, 2));
            _Position += 2;
            return value;
        }

        /// <summary>
        /// Read a 24-bit unsigned integer in big-endian order.
        /// </summary>
        /// <returns>Unsigned 24-bit value widened to 32 bits.</returns>
        public uint ReadUInt24BigEndian()
        {
            EnsureAvailable(3);
            ReadOnlySpan<byte> span = _Buffer.Span.Slice(_Position, 3);
            uint value = ((uint)span[0] << 16) | ((uint)span[1] << 8) | span[2];
            _Position += 3;
            return value;
        }

        /// <summary>
        /// Read a 32-bit unsigned integer in little-endian order.
        /// </summary>
        /// <returns>Unsigned 32-bit value.</returns>
        public uint ReadUInt32()
        {
            EnsureAvailable(4);
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(_Buffer.Span.Slice(_Position, 4));
            _Position += 4;
            return value;
        }

        /// <summary>
        /// Read a 32-bit unsigned integer in big-endian order.
        /// </summary>
        /// <returns>Unsigned 32-bit value.</returns>
        public uint ReadUInt32BigEndian()
        {
            EnsureAvailable(4);
            uint value = BinaryPrimitives.ReadUInt32BigEndian(_Buffer.Span.Slice(_Position, 4));
            _Position += 4;
            return value;
        }

        /// <summary>
        /// Read a 64-bit unsigned integer in little-endian order.
        /// </summary>
        /// <returns>Unsigned 64-bit value.</returns>
        public ulong ReadUInt64()
        {
            EnsureAvailable(8);
            ulong value = BinaryPrimitives.ReadUInt64LittleEndian(_Buffer.Span.Slice(_Position, 8));
            _Position += 8;
            return value;
        }

        /// <summary>
        /// Read a GUID using the Windows little-endian GUID binary layout.
        /// </summary>
        /// <returns>GUID value.</returns>
        public Guid ReadGuid()
        {
            return new Guid(ReadBytes(16));
        }

        /// <summary>
        /// Read a fixed number of bytes.
        /// </summary>
        /// <param name="length">Byte count to read.</param>
        /// <returns>Copied byte array.</returns>
        public byte[] ReadBytes(int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative.");
            }

            EnsureAvailable(length);
            byte[] value = _Buffer.Slice(_Position, length).ToArray();
            _Position += length;
            return value;
        }

        /// <summary>
        /// Skip a fixed number of bytes.
        /// </summary>
        /// <param name="length">Byte count to skip.</param>
        public void Skip(int length)
        {
            if (length < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(length), "Length must be non-negative.");
            }

            EnsureAvailable(length);
            _Position += length;
        }

        private void EnsureAvailable(int byteCount)
        {
            if (RemainingBytes < byteCount)
            {
                throw new ProtocolEncodingException("Attempted to read beyond the end of the buffer.");
            }
        }

        private readonly ReadOnlyMemory<byte> _Buffer;
        private int _Position = 0;
    }
}
