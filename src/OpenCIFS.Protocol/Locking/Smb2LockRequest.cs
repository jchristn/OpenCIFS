namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lock request payload.
    /// </summary>
    public sealed class Smb2LockRequest
    {
        private const ushort StructureSize = 48;
        private const int FixedBodyLength = 24;

        /// <summary>
        /// Reserved lock sequence field for SMB 2.0.2.
        /// </summary>
        public uint LockSequence { get; set; }

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Requested lock elements.
        /// </summary>
        public Smb2LockElement[] Locks
        {
            get
            {
                return _Locks;
            }
            set
            {
                _Locks = value ?? throw new ArgumentNullException(nameof(Locks), "Locks cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the request body to wire format.
        /// </summary>
        /// <returns>Encoded request body.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16(StructureSize);
            writer.WriteUInt16((ushort)Locks.Length);
            writer.WriteUInt32(LockSequence);
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);

            for (int index = 0; index < Locks.Length; index++)
            {
                Smb2LockElement element = Locks[index] ?? throw new ArgumentNullException(nameof(Locks), "Locks cannot contain null entries.");
                writer.WriteBytes(element.ToByteArray());
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse the request body from wire format.
        /// </summary>
        /// <param name="buffer">Encoded request body.</param>
        /// <returns>Parsed request.</returns>
        public static Smb2LockRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < StructureSize)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 lock request.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);

            if (reader.ReadUInt16() != StructureSize)
            {
                throw new ProtocolEncodingException("The SMB2 lock request structure size must be 48 bytes.");
            }

            ushort lockCount = reader.ReadUInt16();
            Smb2LockRequest request = new Smb2LockRequest
            {
                LockSequence = reader.ReadUInt32(),
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64()
            };

            int expectedLength = checked(FixedBodyLength + (lockCount * Smb2LockElement.StructureLength));

            if (buffer.Length != expectedLength)
            {
                throw new ProtocolEncodingException("The SMB2 lock request length does not match the encoded lock count.");
            }

            Smb2LockElement[] locks = new Smb2LockElement[lockCount];

            for (int index = 0; index < lockCount; index++)
            {
                locks[index] = Smb2LockElement.ReadFrom(buffer.Slice(FixedBodyLength + (index * Smb2LockElement.StructureLength), Smb2LockElement.StructureLength));
            }

            request.Locks = locks;
            return request;
        }

        private Smb2LockElement[] _Locks = Array.Empty<Smb2LockElement>();
    }
}
