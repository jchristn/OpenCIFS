namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// SMB1 <c>SMB_COM_LOCKING_ANDX</c> request used to acquire or release byte-range locks plus
    /// to acknowledge oplock breaks issued by the server.
    /// </summary>
    /// <remarks>
    /// MS-CIFS section 2.2.4.32.1. The bounded codec only supports the WordCount=8 shape with
    /// 64-bit lock ranges (LOCKING_ANDX_LARGE_FILES bit 0x10 in <see cref="LockType" />). Each
    /// lock and unlock entry is 20 bytes (Pid 2, Pad 2, OffsetHigh 4, OffsetLow 4, LengthHigh 4,
    /// LengthLow 4) and the bounded codec also supports the older 10-byte shape when the large-files
    /// bit is clear (Pid 2, Offset 4, Length 4) for client compatibility.
    /// </remarks>
    public sealed class Smb1LockingAndXRequest
    {
        private const byte WordCountValue = 0x08;
        private const int ParameterWordsLength = WordCountValue * sizeof(ushort);
        private const int FixedBodyLength = 1 + ParameterWordsLength + sizeof(ushort);
        private const byte AndXNoFurtherCommands = 0xFF;

        /// <summary>
        /// Bit set on <see cref="LockType" /> when entries carry 64-bit OffsetHigh/LengthHigh fields.
        /// </summary>
        public const byte LockTypeLargeFiles = 0x10;

        /// <summary>
        /// Bit set on <see cref="LockType" /> when this request acknowledges an oplock-break
        /// downgrade originated by the server.
        /// </summary>
        public const byte LockTypeOplockRelease = 0x02;

        /// <summary>
        /// Single byte-range lock or unlock entry.
        /// </summary>
        public sealed class LockRange
        {
            /// <summary>
            /// Process identifier owning the lock.
            /// </summary>
            public ushort ProcessId { get; set; }

            /// <summary>
            /// 64-bit byte offset of the locked range.
            /// </summary>
            public ulong Offset { get; set; }

            /// <summary>
            /// 64-bit byte length of the locked range.
            /// </summary>
            public ulong Length { get; set; }
        }

        /// <summary>
        /// SMB1 request header.
        /// </summary>
        public Smb1Header Header
        {
            get
            {
                return _Header;
            }
            set
            {
                _Header = value ?? throw new ArgumentNullException(nameof(Header), "Header cannot be null.");
            }
        }

        /// <summary>
        /// Trailing AndX command code, or <c>0xFF</c> when no further command follows.
        /// </summary>
        public byte AndXCommand { get; set; } = AndXNoFurtherCommands;

        /// <summary>
        /// AndX offset relative to the SMB header start, in bytes.
        /// </summary>
        public ushort AndXOffset { get; set; }

        /// <summary>
        /// SMB1 file identifier returned by the prior open.
        /// </summary>
        public ushort FileId { get; set; }

        /// <summary>
        /// Lock-type bit field. <see cref="LockTypeLargeFiles" /> selects the 64-bit entry shape.
        /// </summary>
        public byte LockType { get; set; } = LockTypeLargeFiles;

        /// <summary>
        /// Oplock level the client is downgrading to when acknowledging an oplock break.
        /// </summary>
        public byte OplockLevel { get; set; }

        /// <summary>
        /// Time, in milliseconds, the server should wait for the lock to become available.
        /// </summary>
        public uint Timeout { get; set; }

        /// <summary>
        /// Byte ranges to release.
        /// </summary>
        public IList<LockRange> Unlocks
        {
            get
            {
                return _Unlocks;
            }
        }

        /// <summary>
        /// Byte ranges to acquire.
        /// </summary>
        public IList<LockRange> Locks
        {
            get
            {
                return _Locks;
            }
        }

        /// <summary>
        /// Serialize the LOCKING_ANDX request to its SMB1 wire format.
        /// </summary>
        /// <returns>Request bytes.</returns>
        public byte[] ToByteArray()
        {
            Smb1HeaderValidator.Validate(Header);

            if (Header.Command != Smb1Command.LockingAndX)
            {
                throw new ProtocolValidationException("The SMB1 LOCKING_ANDX request header command must be SMB_COM_LOCKING_ANDX.", nameof(Header));
            }

            bool largeFiles = (LockType & LockTypeLargeFiles) != 0;
            int entrySize = largeFiles ? 20 : 10;
            int byteCount = (Unlocks.Count + Locks.Count) * entrySize;

            if (byteCount > UInt16.MaxValue)
            {
                throw new ArgumentOutOfRangeException(nameof(Locks), "SMB1 LOCKING_ANDX request lock-range payload exceeds the 16-bit ByteCount field.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(Header.ToByteArray());
            writer.WriteByte(WordCountValue);
            writer.WriteByte(AndXCommand);
            writer.WriteByte(0);
            writer.WriteUInt16(AndXOffset);
            writer.WriteUInt16(FileId);
            writer.WriteByte(LockType);
            writer.WriteByte(OplockLevel);
            writer.WriteUInt32(Timeout);
            writer.WriteUInt16((ushort)Unlocks.Count);
            writer.WriteUInt16((ushort)Locks.Count);
            writer.WriteUInt16((ushort)byteCount);

            foreach (LockRange unlock in Unlocks)
            {
                WriteLockRange(writer, unlock, largeFiles);
            }

            foreach (LockRange lockRange in Locks)
            {
                WriteLockRange(writer, lockRange, largeFiles);
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse an SMB1 LOCKING_ANDX request from its wire bytes.
        /// </summary>
        /// <param name="buffer">Request bytes.</param>
        /// <returns>Parsed request.</returns>
        public static Smb1LockingAndXRequest ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            int minimumLength = ProtocolConstants.Smb1HeaderLength + FixedBodyLength;

            if (buffer.Length < minimumLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB1 LOCKING_ANDX request.");
            }

            Smb1Header header = Smb1Header.ReadFrom(buffer.Slice(0, ProtocolConstants.Smb1HeaderLength));
            Smb1HeaderValidator.Validate(header);

            if (header.Command != Smb1Command.LockingAndX)
            {
                throw new ProtocolEncodingException("The SMB1 message does not carry an SMB_COM_LOCKING_ANDX command.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer.Slice(ProtocolConstants.Smb1HeaderLength));
            byte wordCount = reader.ReadByte();

            if (wordCount != WordCountValue)
            {
                throw new ProtocolEncodingException("The SMB1 LOCKING_ANDX request must use WordCount=8.");
            }

            byte andXCommand = reader.ReadByte();
            reader.ReadByte();
            ushort andXOffset = reader.ReadUInt16();
            ushort fileId = reader.ReadUInt16();
            byte lockType = reader.ReadByte();
            byte oplockLevel = reader.ReadByte();
            uint timeout = reader.ReadUInt32();
            ushort unlockCount = reader.ReadUInt16();
            ushort lockCount = reader.ReadUInt16();
            ushort byteCount = reader.ReadUInt16();

            if (byteCount != reader.RemainingBytes)
            {
                throw new ProtocolEncodingException("The SMB1 LOCKING_ANDX request ByteCount does not match the remaining payload length.");
            }

            bool largeFiles = (lockType & LockTypeLargeFiles) != 0;
            int entrySize = largeFiles ? 20 : 10;
            int expectedByteCount = (unlockCount + lockCount) * entrySize;

            if (expectedByteCount != byteCount)
            {
                throw new ProtocolEncodingException("The SMB1 LOCKING_ANDX request ByteCount does not match the declared lock and unlock counts.");
            }

            Smb1LockingAndXRequest request = new Smb1LockingAndXRequest
            {
                Header = header,
                AndXCommand = andXCommand,
                AndXOffset = andXOffset,
                FileId = fileId,
                LockType = lockType,
                OplockLevel = oplockLevel,
                Timeout = timeout
            };

            for (int index = 0; index < unlockCount; index++)
            {
                request.Unlocks.Add(ReadLockRange(ref reader, largeFiles));
            }

            for (int index = 0; index < lockCount; index++)
            {
                request.Locks.Add(ReadLockRange(ref reader, largeFiles));
            }

            return request;
        }

        private static void WriteLockRange(LittleEndianWriter writer, LockRange range, bool largeFiles)
        {
            if (largeFiles)
            {
                writer.WriteUInt16(range.ProcessId);
                writer.WriteUInt16(0);
                writer.WriteUInt32(unchecked((uint)((range.Offset >> 32) & 0xFFFFFFFFU)));
                writer.WriteUInt32(unchecked((uint)(range.Offset & 0xFFFFFFFFU)));
                writer.WriteUInt32(unchecked((uint)((range.Length >> 32) & 0xFFFFFFFFU)));
                writer.WriteUInt32(unchecked((uint)(range.Length & 0xFFFFFFFFU)));
            }
            else
            {
                writer.WriteUInt16(range.ProcessId);
                writer.WriteUInt32(unchecked((uint)(range.Offset & 0xFFFFFFFFU)));
                writer.WriteUInt32(unchecked((uint)(range.Length & 0xFFFFFFFFU)));
            }
        }

        private static LockRange ReadLockRange(ref LittleEndianReader reader, bool largeFiles)
        {
            if (largeFiles)
            {
                ushort pid = reader.ReadUInt16();
                reader.ReadUInt16();
                uint offsetHigh = reader.ReadUInt32();
                uint offsetLow = reader.ReadUInt32();
                uint lengthHigh = reader.ReadUInt32();
                uint lengthLow = reader.ReadUInt32();
                return new LockRange
                {
                    ProcessId = pid,
                    Offset = ((ulong)offsetHigh << 32) | offsetLow,
                    Length = ((ulong)lengthHigh << 32) | lengthLow
                };
            }
            else
            {
                ushort pid = reader.ReadUInt16();
                uint offset = reader.ReadUInt32();
                uint length = reader.ReadUInt32();
                return new LockRange
                {
                    ProcessId = pid,
                    Offset = offset,
                    Length = length
                };
            }
        }

        private readonly List<LockRange> _Unlocks = new List<LockRange>();
        private readonly List<LockRange> _Locks = new List<LockRange>();
        private Smb1Header _Header = new Smb1Header
        {
            Command = Smb1Command.LockingAndX,
            Flags2 = Smb1HeaderFlags2.Unicode | Smb1HeaderFlags2.NtStatus | Smb1HeaderFlags2.ExtendedSecurity
        };
    }
}
