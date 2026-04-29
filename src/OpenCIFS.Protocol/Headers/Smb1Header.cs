namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB1 wire header.
    /// </summary>
    public sealed class Smb1Header
    {
        /// <summary>
        /// SMB1 command identifier.
        /// </summary>
        public Smb1Command Command { get; set; } = Smb1Command.Negotiate;

        /// <summary>
        /// NTSTATUS code.
        /// </summary>
        public NtStatus Status { get; set; } = NtStatus.Success;

        /// <summary>
        /// SMB1 flags.
        /// </summary>
        public Smb1HeaderFlags Flags { get; set; } = Smb1HeaderFlags.None;

        /// <summary>
        /// SMB1 flags2.
        /// </summary>
        public Smb1HeaderFlags2 Flags2 { get; set; } = Smb1HeaderFlags2.None;

        /// <summary>
        /// High process identifier bits.
        /// </summary>
        public ushort ProcessIdHigh { get; set; } = 0;

        /// <summary>
        /// Signature or reserved field.
        /// Must be 8 bytes.
        /// </summary>
        public byte[] Signature
        {
            get
            {
                return _Signature;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Signature), "Signature cannot be null.");
                }

                if (value.Length != 8)
                {
                    throw new ArgumentOutOfRangeException(nameof(Signature), "SMB1 signatures must be exactly 8 bytes.");
                }

                _Signature = value;
            }
        }

        /// <summary>
        /// Tree identifier.
        /// </summary>
        public ushort TreeId { get; set; } = 0;

        /// <summary>
        /// Low process identifier bits.
        /// </summary>
        public ushort ProcessIdLow { get; set; } = 0;

        /// <summary>
        /// User identifier.
        /// </summary>
        public ushort UserId { get; set; } = 0;

        /// <summary>
        /// Multiplex identifier.
        /// </summary>
        public ushort MultiplexId { get; set; } = 0;

        /// <summary>
        /// Serialize the header to its 32-byte wire form.
        /// </summary>
        /// <returns>Header bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(ProtocolConstants.Smb1ProtocolId);
            writer.WriteByte((byte)Command);
            writer.WriteUInt32((uint)Status);
            writer.WriteByte((byte)Flags);
            writer.WriteUInt16((ushort)Flags2);
            writer.WriteUInt16(ProcessIdHigh);
            writer.WriteBytes(Signature);
            writer.WriteUInt16(0);
            writer.WriteUInt16(TreeId);
            writer.WriteUInt16(ProcessIdLow);
            writer.WriteUInt16(UserId);
            writer.WriteUInt16(MultiplexId);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the header from a binary buffer.
        /// </summary>
        /// <param name="buffer">Header bytes.</param>
        /// <returns>Parsed header.</returns>
        public static Smb1Header ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < ProtocolConstants.Smb1HeaderLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 header.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            byte[] protocolId = reader.ReadBytes(4);

            if (!MatchesProtocol(protocolId, ProtocolConstants.Smb1ProtocolId))
            {
                throw new ProtocolEncodingException("The buffer does not contain a valid SMB1 protocol identifier.");
            }

            Smb1Header header = new Smb1Header
            {
                Command = (Smb1Command)reader.ReadByte(),
                Status = (NtStatus)reader.ReadUInt32(),
                Flags = (Smb1HeaderFlags)reader.ReadByte(),
                Flags2 = (Smb1HeaderFlags2)reader.ReadUInt16(),
                ProcessIdHigh = reader.ReadUInt16(),
                Signature = reader.ReadBytes(8)
            };

            reader.Skip(2);
            header.TreeId = reader.ReadUInt16();
            header.ProcessIdLow = reader.ReadUInt16();
            header.UserId = reader.ReadUInt16();
            header.MultiplexId = reader.ReadUInt16();
            return header;
        }

        private static bool MatchesProtocol(byte[] protocolId, byte[] expected)
        {
            if (protocolId.Length != expected.Length)
            {
                return false;
            }

            for (int index = 0; index < expected.Length; index++)
            {
                if (protocolId[index] != expected[index])
                {
                    return false;
                }
            }

            return true;
        }

        private byte[] _Signature = new byte[8];
    }
}

