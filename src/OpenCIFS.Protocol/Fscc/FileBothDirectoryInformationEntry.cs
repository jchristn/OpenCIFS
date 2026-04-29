namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// FILE_BOTH_DIR_INFORMATION entry.
    /// </summary>
    public sealed class FileBothDirectoryInformationEntry
    {
        private const int FixedBodyLength = 94;
        private const int ShortNameFieldLength = 24;

        /// <summary>
        /// File index.
        /// </summary>
        public uint FileIndex { get; set; }

        /// <summary>
        /// Creation time in FILETIME form.
        /// </summary>
        public ulong CreationTime { get; set; }

        /// <summary>
        /// Last-access time in FILETIME form.
        /// </summary>
        public ulong LastAccessTime { get; set; }

        /// <summary>
        /// Last-write time in FILETIME form.
        /// </summary>
        public ulong LastWriteTime { get; set; }

        /// <summary>
        /// Change time in FILETIME form.
        /// </summary>
        public ulong ChangeTime { get; set; }

        /// <summary>
        /// End-of-file size.
        /// </summary>
        public ulong EndOfFile { get; set; }

        /// <summary>
        /// Allocation size.
        /// </summary>
        public ulong AllocationSize { get; set; }

        /// <summary>
        /// File attributes.
        /// </summary>
        public FileAttributes FileAttributes { get; set; } = FileAttributes.None;

        /// <summary>
        /// Extended attribute size or reparse-tag field.
        /// </summary>
        public uint EaSize { get; set; }

        /// <summary>
        /// Short 8.3 file name.
        /// </summary>
        public string ShortName
        {
            get
            {
                return _ShortName;
            }
            set
            {
                _ShortName = value ?? throw new ArgumentNullException(nameof(ShortName), "ShortName cannot be null.");
            }
        }

        /// <summary>
        /// File name.
        /// </summary>
        public string FileName
        {
            get
            {
                return _FileName;
            }
            set
            {
                _FileName = value ?? throw new ArgumentNullException(nameof(FileName), "FileName cannot be null.");
            }
        }

        /// <summary>
        /// Encode a list of entries into a directory-information buffer.
        /// </summary>
        /// <param name="entries">Entries to encode.</param>
        /// <returns>Encoded buffer.</returns>
        public static byte[] EncodeEntries(IReadOnlyList<FileBothDirectoryInformationEntry> entries)
        {
            if (entries == null)
            {
                throw new ArgumentNullException(nameof(entries), "Entries cannot be null.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();

            for (int index = 0; index < entries.Count; index++)
            {
                FileBothDirectoryInformationEntry entry = entries[index] ?? throw new ArgumentNullException(nameof(entries), "Entries cannot contain null values.");
                byte[] fileNameBytes = Encoding.Unicode.GetBytes(entry.FileName);
                byte[] shortNameBytes = EncodeShortName(entry.ShortName);
                int rawLength = checked(FixedBodyLength + fileNameBytes.Length);
                bool hasNext = index < entries.Count - 1;
                int paddedLength = hasNext ? Align8(rawLength) : rawLength;

                writer.WriteUInt32(hasNext ? (uint)paddedLength : 0U);
                writer.WriteUInt32(entry.FileIndex);
                writer.WriteUInt64(entry.CreationTime);
                writer.WriteUInt64(entry.LastAccessTime);
                writer.WriteUInt64(entry.LastWriteTime);
                writer.WriteUInt64(entry.ChangeTime);
                writer.WriteUInt64(entry.EndOfFile);
                writer.WriteUInt64(entry.AllocationSize);
                writer.WriteUInt32((uint)entry.FileAttributes);
                writer.WriteUInt32((uint)fileNameBytes.Length);
                writer.WriteUInt32(entry.EaSize);
                writer.WriteByte((byte)shortNameBytes.Length);
                writer.WriteByte(0);
                writer.WriteBytes(PadShortName(shortNameBytes));
                writer.WriteBytes(fileNameBytes);

                for (int paddingIndex = rawLength; paddingIndex < paddedLength; paddingIndex++)
                {
                    writer.WriteByte(0);
                }
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Decode a directory-information buffer into entries.
        /// </summary>
        /// <param name="buffer">Encoded buffer.</param>
        /// <returns>Decoded entries.</returns>
        public static FileBothDirectoryInformationEntry[] DecodeEntries(ReadOnlyMemory<byte> buffer)
        {
            List<FileBothDirectoryInformationEntry> entries = new List<FileBothDirectoryInformationEntry>();
            int offset = 0;

            while (offset < buffer.Length)
            {
                if (buffer.Length - offset < FixedBodyLength)
                {
                    throw new ProtocolEncodingException("The FILE_BOTH_DIR_INFORMATION buffer does not contain a complete entry header.");
                }

                ReadOnlyMemory<byte> remainingBuffer = buffer.Slice(offset);
                LittleEndianReader reader = new LittleEndianReader(remainingBuffer);
                uint nextEntryOffset = reader.ReadUInt32();
                FileBothDirectoryInformationEntry entry = new FileBothDirectoryInformationEntry
                {
                    FileIndex = reader.ReadUInt32(),
                    CreationTime = reader.ReadUInt64(),
                    LastAccessTime = reader.ReadUInt64(),
                    LastWriteTime = reader.ReadUInt64(),
                    ChangeTime = reader.ReadUInt64(),
                    EndOfFile = reader.ReadUInt64(),
                    AllocationSize = reader.ReadUInt64(),
                    FileAttributes = (FileAttributes)reader.ReadUInt32()
                };
                uint fileNameLength = reader.ReadUInt32();
                entry.EaSize = reader.ReadUInt32();
                byte shortNameLength = reader.ReadByte();
                reader.ReadByte();
                byte[] shortNameField = reader.ReadBytes(ShortNameFieldLength);

                if ((fileNameLength % 2) != 0 || (shortNameLength % 2) != 0 || shortNameLength > ShortNameFieldLength)
                {
                    throw new ProtocolEncodingException("The FILE_BOTH_DIR_INFORMATION entry contains an invalid UTF-16 name length.");
                }

                int fileNameLengthValue = checked((int)fileNameLength);

                if (FixedBodyLength + fileNameLengthValue > remainingBuffer.Length)
                {
                    throw new ProtocolEncodingException("The FILE_BOTH_DIR_INFORMATION entry name exceeds the available payload.");
                }

                entry.ShortName = Encoding.Unicode.GetString(shortNameField, 0, shortNameLength);
                entry.FileName = Encoding.Unicode.GetString(remainingBuffer.Slice(FixedBodyLength, fileNameLengthValue).ToArray());
                entries.Add(entry);

                if (nextEntryOffset == 0)
                {
                    if (offset + FixedBodyLength + fileNameLengthValue != buffer.Length)
                    {
                        throw new ProtocolEncodingException("The FILE_BOTH_DIR_INFORMATION buffer contains trailing bytes after the terminal entry.");
                    }

                    break;
                }

                if ((nextEntryOffset % 8) != 0 || nextEntryOffset < FixedBodyLength + fileNameLengthValue)
                {
                    throw new ProtocolEncodingException("The FILE_BOTH_DIR_INFORMATION entry NextEntryOffset is invalid.");
                }

                offset = checked(offset + (int)nextEntryOffset);

                if (offset > buffer.Length)
                {
                    throw new ProtocolEncodingException("The FILE_BOTH_DIR_INFORMATION entry NextEntryOffset exceeds the available payload.");
                }
            }

            return entries.ToArray();
        }

        private static byte[] EncodeShortName(string value)
        {
            byte[] shortNameBytes = Encoding.Unicode.GetBytes(value);

            if (shortNameBytes.Length > ShortNameFieldLength)
            {
                throw new ProtocolValidationException("The FILE_BOTH_DIR_INFORMATION short name must fit within 24 bytes.", nameof(value));
            }

            return shortNameBytes;
        }

        private static byte[] PadShortName(byte[] shortNameBytes)
        {
            byte[] padded = new byte[ShortNameFieldLength];
            Buffer.BlockCopy(shortNameBytes, 0, padded, 0, shortNameBytes.Length);
            return padded;
        }

        private static int Align8(int value)
        {
            int remainder = value % 8;
            return remainder == 0 ? value : checked(value + (8 - remainder));
        }

        private string _ShortName = string.Empty;
        private string _FileName = string.Empty;
    }
}
