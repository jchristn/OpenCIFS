namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lease-break notification payload sent by the server.
    /// </summary>
    public sealed class Smb2LeaseBreakNotification
    {
        private const ushort StructureSize = 44;

        /// <summary>
        /// Reserved epoch field for SMB 2.1. Must be zero.
        /// </summary>
        public ushort NewEpoch { get; set; }

        /// <summary>
        /// Lease-break notification flags.
        /// </summary>
        public Smb2LeaseBreakNotificationFlags Flags { get; set; } = Smb2LeaseBreakNotificationFlags.None;

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
        /// Current granted lease state.
        /// </summary>
        public Smb2LeaseState CurrentLeaseState { get; set; } = Smb2LeaseState.None;

        /// <summary>
        /// New lease state requested by the server.
        /// </summary>
        public Smb2LeaseState NewLeaseState { get; set; } = Smb2LeaseState.None;

        /// <summary>
        /// Reserved break-reason hint. Must be zero for SMB 2.1.
        /// </summary>
        public uint BreakReason { get; set; }

        /// <summary>
        /// Reserved access-mask hint. Must be zero for SMB 2.1.
        /// </summary>
        public uint AccessMaskHint { get; set; }

        /// <summary>
        /// Reserved share-mask hint. Must be zero for SMB 2.1.
        /// </summary>
        public uint ShareMaskHint { get; set; }

        /// <summary>
        /// Serialize the notification payload to wire format.
        /// </summary>
        /// <returns>Notification bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16(NewEpoch);
            writer.WriteUInt32((uint)Flags);
            writer.WriteBytes(LeaseKey);
            writer.WriteUInt32((uint)CurrentLeaseState);
            writer.WriteUInt32((uint)NewLeaseState);
            writer.WriteUInt32(BreakReason);
            writer.WriteUInt32(AccessMaskHint);
            writer.WriteUInt32(ShareMaskHint);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the notification payload from wire format.
        /// </summary>
        /// <param name="buffer">Notification bytes.</param>
        /// <returns>Parsed notification.</returns>
        public static Smb2LeaseBreakNotification ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 lease-break notification.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 lease-break notification structure size must be 44 bytes.");
            }

            Smb2LeaseBreakNotification notification = new Smb2LeaseBreakNotification
            {
                NewEpoch = reader.ReadUInt16(),
                Flags = (Smb2LeaseBreakNotificationFlags)reader.ReadUInt32(),
                LeaseKey = reader.ReadBytes(16),
                CurrentLeaseState = (Smb2LeaseState)reader.ReadUInt32(),
                NewLeaseState = (Smb2LeaseState)reader.ReadUInt32(),
                BreakReason = reader.ReadUInt32(),
                AccessMaskHint = reader.ReadUInt32(),
                ShareMaskHint = reader.ReadUInt32()
            };

            return notification;
        }
        private byte[] _LeaseKey = new byte[16];
    }
}
