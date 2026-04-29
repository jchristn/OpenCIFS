namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2/3 wire header.
    /// </summary>
    public sealed class Smb2Header
    {
        /// <summary>
        /// Credit charge.
        /// In SMB 2.0.2 this field is reserved and remains <c>0</c>.
        /// In later dialects it indicates the number of credits consumed by the request.
        /// Minimum value: <c>0</c>.
        /// Maximum value: <c>65535</c>.
        /// </summary>
        public ushort CreditCharge
        {
            get
            {
                return _CreditCharge;
            }
            set
            {
                _CreditCharge = value;
            }
        }

        /// <summary>
        /// NTSTATUS code for responses.
        /// </summary>
        public NtStatus Status { get; set; } = NtStatus.Success;

        /// <summary>
        /// SMB2/3 command identifier.
        /// </summary>
        public Smb2Command Command { get; set; } = Smb2Command.Negotiate;

        /// <summary>
        /// Requested or granted credits.
        /// </summary>
        public ushort CreditRequest { get; set; } = 1;

        /// <summary>
        /// SMB2/3 header flags.
        /// </summary>
        public Smb2HeaderFlags Flags { get; set; } = Smb2HeaderFlags.None;

        /// <summary>
        /// Offset to the next compounded command.
        /// </summary>
        public uint NextCommand { get; set; } = 0;

        /// <summary>
        /// Message identifier.
        /// </summary>
        public ulong MessageId { get; set; } = 0;

        /// <summary>
        /// Process identifier for synchronous requests.
        /// </summary>
        public uint ProcessId { get; set; } = 0;

        /// <summary>
        /// Tree identifier.
        /// </summary>
        public uint TreeId { get; set; } = 0;

        /// <summary>
        /// Asynchronous identifier for async requests and responses.
        /// </summary>
        public ulong AsyncId { get; set; } = 0;

        /// <summary>
        /// Session identifier.
        /// </summary>
        public ulong SessionId { get; set; } = 0;

        /// <summary>
        /// Message signature.
        /// Must be 16 bytes.
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

                if (value.Length != 16)
                {
                    throw new ArgumentOutOfRangeException(nameof(Signature), "SMB2/3 signatures must be exactly 16 bytes.");
                }

                _Signature = value;
            }
        }

        /// <summary>
        /// Serialize the header to its 64-byte wire form.
        /// </summary>
        /// <returns>Header bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(ProtocolConstants.Smb2ProtocolId);
            writer.WriteUInt16(64);
            writer.WriteUInt16(CreditCharge);
            writer.WriteUInt32((uint)Status);
            writer.WriteUInt16((ushort)Command);
            writer.WriteUInt16(CreditRequest);
            writer.WriteUInt32((uint)Flags);
            writer.WriteUInt32(NextCommand);
            writer.WriteUInt64(MessageId);

            if ((Flags & Smb2HeaderFlags.AsyncCommand) != 0)
            {
                writer.WriteUInt64(AsyncId);
            }
            else
            {
                writer.WriteUInt32(ProcessId);
                writer.WriteUInt32(TreeId);
            }

            writer.WriteUInt64(SessionId);
            writer.WriteBytes(Signature);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the header from a binary buffer.
        /// </summary>
        /// <param name="buffer">Header bytes.</param>
        /// <returns>Parsed header.</returns>
        public static Smb2Header ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < ProtocolConstants.Smb2HeaderLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2/3 header.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            byte[] protocolId = reader.ReadBytes(4);

            if (!MatchesProtocol(protocolId, ProtocolConstants.Smb2ProtocolId))
            {
                throw new ProtocolEncodingException("The buffer does not contain a valid SMB2/3 protocol identifier.");
            }

            ushort structureSize = reader.ReadUInt16();

            if (structureSize != 64)
            {
                throw new ProtocolEncodingException("The SMB2/3 structure size must be 64 bytes.");
            }

            ushort creditCharge = reader.ReadUInt16();
            NtStatus status = (NtStatus)reader.ReadUInt32();
            Smb2Command command = (Smb2Command)reader.ReadUInt16();
            ushort creditRequest = reader.ReadUInt16();
            Smb2HeaderFlags flags = (Smb2HeaderFlags)reader.ReadUInt32();
            uint nextCommand = reader.ReadUInt32();
            ulong messageId = reader.ReadUInt64();
            Smb2Header header = new Smb2Header
            {
                CreditCharge = creditCharge,
                Status = status,
                Command = command,
                CreditRequest = creditRequest,
                Flags = flags,
                NextCommand = nextCommand,
                MessageId = messageId
            };

            if ((flags & Smb2HeaderFlags.AsyncCommand) != 0)
            {
                header.AsyncId = reader.ReadUInt64();
            }
            else
            {
                header.ProcessId = reader.ReadUInt32();
                header.TreeId = reader.ReadUInt32();
            }

            header.SessionId = reader.ReadUInt64();
            header.Signature = reader.ReadBytes(16);
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

        private ushort _CreditCharge = 0;
        private byte[] _Signature = new byte[16];
    }
}
