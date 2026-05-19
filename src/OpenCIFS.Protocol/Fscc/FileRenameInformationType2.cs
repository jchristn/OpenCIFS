namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// FILE_RENAME_INFORMATION_TYPE_2 payload.
    /// </summary>
    public sealed class FileRenameInformationType2
    {
        private const int FixedBodyLength = 20;

        /// <summary>
        /// Whether an existing destination may be replaced.
        /// </summary>
        public bool ReplaceIfExists { get; set; }

        /// <summary>
        /// Root directory identifier.
        /// </summary>
        public ulong RootDirectory { get; set; }

        /// <summary>
        /// Target file name.
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
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] fileNameBytes = Encoding.Unicode.GetBytes(FileName);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteByte(ReplaceIfExists ? (byte)1 : (byte)0);

            for (int index = 0; index < 7; index++)
            {
                writer.WriteByte(0);
            }

            writer.WriteUInt64(RootDirectory);
            writer.WriteUInt32((uint)fileNameBytes.Length);
            writer.WriteBytes(fileNameBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileRenameInformationType2 ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete FILE_RENAME_INFORMATION_TYPE_2 structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            byte replaceIfExists = reader.ReadByte();

            if (replaceIfExists > 1)
            {
                throw new ProtocolEncodingException("FILE_RENAME_INFORMATION_TYPE_2 contains an invalid ReplaceIfExists value.");
            }

            reader.Skip(7);
            ulong rootDirectory = reader.ReadUInt64();
            uint fileNameLength = reader.ReadUInt32();

            if ((fileNameLength % 2) != 0)
            {
                throw new ProtocolEncodingException("FILE_RENAME_INFORMATION_TYPE_2 contains an invalid UTF-16 file-name length.");
            }

            if (fileNameLength > Int32.MaxValue)
            {
                throw new ProtocolEncodingException("FILE_RENAME_INFORMATION_TYPE_2 length exceeds the available payload.");
            }

            int requiredLength = checked(FixedBodyLength + (int)fileNameLength);

            if (requiredLength > buffer.Length)
            {
                throw new ProtocolEncodingException("FILE_RENAME_INFORMATION_TYPE_2 length exceeds the available payload.");
            }

            if (requiredLength < buffer.Length)
            {
                ReadOnlySpan<byte> trailingBytes = buffer.Span.Slice(requiredLength);

                for (int index = 0; index < trailingBytes.Length; index++)
                {
                    if (trailingBytes[index] != 0)
                    {
                        throw new ProtocolEncodingException("FILE_RENAME_INFORMATION_TYPE_2 contains non-zero trailing bytes beyond FileNameLength.");
                    }
                }
            }

            return new FileRenameInformationType2
            {
                ReplaceIfExists = replaceIfExists != 0,
                RootDirectory = rootDirectory,
                FileName = Encoding.Unicode.GetString(buffer.Slice(FixedBodyLength, checked((int)fileNameLength)).ToArray())
            };
        }

        private string _FileName = string.Empty;
    }
}
