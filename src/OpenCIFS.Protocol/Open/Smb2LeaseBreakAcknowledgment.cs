namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lease-break acknowledgment payload sent by the client.
    /// </summary>
    public sealed class Smb2LeaseBreakAcknowledgment
    {
        private const ushort StructureSize = 36;

        /// <summary>
        /// Lease key bytes.
        /// </summary>
        public byte[] LeaseKey
        {
            get
            {
                return _LeaseKey;
            }
            set
            {
                _LeaseKey = value ?? throw new ArgumentNullException(nameof(LeaseKey), "LeaseKey cannot be null.");
            }
        }

        /// <summary>
        /// Acknowledged lease state.
        /// </summary>
        public Smb2LeaseState LeaseState { get; set; } = Smb2LeaseState.None;

        /// <summary>
        /// Reserved lease duration field. Must be zero for SMB 2.1.
        /// </summary>
        public ulong LeaseDuration { get; set; }

        /// <summary>
        /// Serialize the acknowledgment payload to wire format.
        /// </summary>
        /// <returns>Acknowledgment bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(0);
            writer.WriteUInt32(0);
            writer.WriteBytes(LeaseKey);
            writer.WriteUInt32((uint)LeaseState);
            writer.WriteUInt64(LeaseDuration);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the acknowledgment payload from wire format.
        /// </summary>
        /// <param name="buffer">Acknowledgment bytes.</param>
        /// <returns>Parsed acknowledgment.</returns>
        public static Smb2LeaseBreakAcknowledgment ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 lease-break acknowledgment.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 lease-break acknowledgment structure size must be 36 bytes.");
            }

            reader.Skip(2);
            reader.Skip(4);

            return new Smb2LeaseBreakAcknowledgment
            {
                LeaseKey = reader.ReadBytes(16),
                LeaseState = (Smb2LeaseState)reader.ReadUInt32(),
                LeaseDuration = reader.ReadUInt64()
            };
        }

        private byte[] _LeaseKey = new byte[16];
    }
}
