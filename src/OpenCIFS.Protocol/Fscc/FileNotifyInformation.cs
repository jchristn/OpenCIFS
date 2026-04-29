namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;
    using System.Text;

    /// <summary>
    /// FILE_NOTIFY_INFORMATION entry.
    /// </summary>
    public sealed class FileNotifyInformation
    {
        private const int FixedBodyLength = 12;

        /// <summary>
        /// Notify action.
        /// </summary>
        public FileNotifyAction Action { get; set; } = FileNotifyAction.Modified;

        /// <summary>
        /// Relative path from the watched directory.
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
        /// Encode a list of notify entries to a buffer.
        /// </summary>
        /// <param name="entries">Entries to encode.</param>
        /// <returns>Encoded buffer.</returns>
        public static byte[] EncodeEntries(IReadOnlyList<FileNotifyInformation> entries)
        {
            if (entries == null)
            {
                throw new ArgumentNullException(nameof(entries), "Entries cannot be null.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();

            for (int index = 0; index < entries.Count; index++)
            {
                FileNotifyInformation entry = entries[index] ?? throw new ArgumentNullException(nameof(entries), "Entries cannot contain null values.");
                byte[] fileNameBytes = Encoding.Unicode.GetBytes(entry.FileName);
                int rawLength = checked(FixedBodyLength + fileNameBytes.Length);
                bool hasNext = index < entries.Count - 1;
                int paddedLength = hasNext ? Align4(rawLength) : rawLength;

                writer.WriteUInt32(hasNext ? (uint)paddedLength : 0U);
                writer.WriteUInt32((uint)entry.Action);
                writer.WriteUInt32((uint)fileNameBytes.Length);
                writer.WriteBytes(fileNameBytes);

                for (int paddingIndex = rawLength; paddingIndex < paddedLength; paddingIndex++)
                {
                    writer.WriteByte(0);
                }
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Decode a notify buffer into entries.
        /// </summary>
        /// <param name="buffer">Encoded buffer.</param>
        /// <returns>Decoded entries.</returns>
        public static FileNotifyInformation[] DecodeEntries(ReadOnlyMemory<byte> buffer)
        {
            List<FileNotifyInformation> entries = new List<FileNotifyInformation>();
            int offset = 0;

            while (offset < buffer.Length)
            {
                if (buffer.Length - offset < FixedBodyLength)
                {
                    throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION buffer does not contain a complete entry header.");
                }

                ReadOnlyMemory<byte> remainingBuffer = buffer.Slice(offset);
                LittleEndianReader reader = new LittleEndianReader(remainingBuffer);
                uint nextEntryOffset = reader.ReadUInt32();
                FileNotifyAction action = (FileNotifyAction)reader.ReadUInt32();
                uint fileNameLength = reader.ReadUInt32();

                if (!Enum.IsDefined(typeof(FileNotifyAction), action))
                {
                    throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION entry action is not recognized.");
                }

                if ((fileNameLength % 2) != 0)
                {
                    throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION entry contains an invalid UTF-16 file-name length.");
                }

                int fileNameLengthValue = checked((int)fileNameLength);

                if (FixedBodyLength + fileNameLengthValue > remainingBuffer.Length)
                {
                    throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION entry name exceeds the available payload.");
                }

                FileNotifyInformation entry = new FileNotifyInformation
                {
                    Action = action,
                    FileName = Encoding.Unicode.GetString(remainingBuffer.Slice(FixedBodyLength, fileNameLengthValue).ToArray())
                };
                entries.Add(entry);

                if (nextEntryOffset == 0)
                {
                    if (offset + FixedBodyLength + fileNameLengthValue != buffer.Length)
                    {
                        throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION buffer contains trailing bytes after the terminal entry.");
                    }

                    break;
                }

                if ((nextEntryOffset % 4) != 0 || nextEntryOffset < FixedBodyLength + fileNameLengthValue)
                {
                    throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION entry NextEntryOffset is invalid.");
                }

                offset = checked(offset + (int)nextEntryOffset);

                if (offset > buffer.Length)
                {
                    throw new ProtocolEncodingException("The FILE_NOTIFY_INFORMATION entry NextEntryOffset exceeds the available payload.");
                }
            }

            return entries.ToArray();
        }

        private static int Align4(int value)
        {
            int remainder = value % 4;
            return remainder == 0 ? value : checked(value + (4 - remainder));
        }

        private string _FileName = string.Empty;
    }
}
