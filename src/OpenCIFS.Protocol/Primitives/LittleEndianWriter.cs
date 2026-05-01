namespace OpenCIFS.Protocol
{
    using System;
    using System.Buffers.Binary;

    /// <summary>
    /// Writes primitive values to a binary SMB/CIFS payload buffer.
    /// </summary>
    public sealed class LittleEndianWriter
    {
        /// <summary>
        /// Initialize the writer.
        /// </summary>
        public LittleEndianWriter()
        {
        }

        /// <summary>
        /// Current written byte count.
        /// </summary>
        public int Length
        {
            get
            {
                return _Position;
            }
        }

        /// <summary>
        /// Write a single byte.
        /// </summary>
        /// <param name="value">Byte value.</param>
        public void WriteByte(byte value)
        {
            EnsureCapacity(1);
            _Buffer[_Position] = value;
            _Position += 1;
        }

        /// <summary>
        /// Write a 16-bit unsigned integer in little-endian order.
        /// </summary>
        /// <param name="value">Value to write.</param>
        public void WriteUInt16(ushort value)
        {
            EnsureCapacity(2);
            BinaryPrimitives.WriteUInt16LittleEndian(_Buffer.AsSpan(_Position, 2), value);
            _Position += 2;
        }

        /// <summary>
        /// Write a 24-bit unsigned integer in big-endian order.
        /// </summary>
        /// <param name="value">Value to write. Maximum supported value: <c>16777215</c>.</param>
        public void WriteUInt24BigEndian(uint value)
        {
            if (value > 0x00FFFFFFU)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The value exceeds the 24-bit maximum.");
            }

            EnsureCapacity(3);
            _Buffer[_Position] = (byte)((value >> 16) & 0xFFU);
            _Buffer[_Position + 1] = (byte)((value >> 8) & 0xFFU);
            _Buffer[_Position + 2] = (byte)(value & 0xFFU);
            _Position += 3;
        }

        /// <summary>
        /// Write a 32-bit unsigned integer in little-endian order.
        /// </summary>
        /// <param name="value">Value to write.</param>
        public void WriteUInt32(uint value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteUInt32LittleEndian(_Buffer.AsSpan(_Position, 4), value);
            _Position += 4;
        }

        /// <summary>
        /// Write a 32-bit unsigned integer in big-endian order.
        /// </summary>
        /// <param name="value">Value to write.</param>
        public void WriteUInt32BigEndian(uint value)
        {
            EnsureCapacity(4);
            BinaryPrimitives.WriteUInt32BigEndian(_Buffer.AsSpan(_Position, 4), value);
            _Position += 4;
        }

        /// <summary>
        /// Write a 64-bit unsigned integer in little-endian order.
        /// </summary>
        /// <param name="value">Value to write.</param>
        public void WriteUInt64(ulong value)
        {
            EnsureCapacity(8);
            BinaryPrimitives.WriteUInt64LittleEndian(_Buffer.AsSpan(_Position, 8), value);
            _Position += 8;
        }

        /// <summary>
        /// Write a GUID using the Windows little-endian GUID binary layout.
        /// </summary>
        /// <param name="value">GUID value.</param>
        public void WriteGuid(Guid value)
        {
            WriteBytes(value.ToByteArray());
        }

        /// <summary>
        /// Write raw bytes.
        /// </summary>
        /// <param name="value">Bytes to write.</param>
        public void WriteBytes(ReadOnlySpan<byte> value)
        {
            EnsureCapacity(value.Length);
            value.CopyTo(_Buffer.AsSpan(_Position, value.Length));
            _Position += value.Length;
        }

        /// <summary>
        /// Return the written payload as a byte array.
        /// </summary>
        /// <returns>Written byte array.</returns>
        public byte[] ToArray()
        {
            byte[] value = new byte[_Position];
            Array.Copy(_Buffer, value, _Position);
            return value;
        }

        private void EnsureCapacity(int requiredAdditionalBytes)
        {
            if (_Position + requiredAdditionalBytes <= _Buffer.Length)
            {
                return;
            }

            int newLength = Math.Max(_Buffer.Length * 2, _Position + requiredAdditionalBytes);
            Array.Resize(ref _Buffer, newLength);
        }

        private byte[] _Buffer = new byte[64];
        private int _Position = 0;
    }
}
