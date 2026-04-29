namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// FILE_NAME_INFORMATION payload.
    /// </summary>
    public sealed class FileNameInformation
    {
        private const int FixedBodyLength = 4;

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
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] fileNameBytes = Encoding.Unicode.GetBytes(FileName);
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32((uint)fileNameBytes.Length);
            writer.WriteBytes(fileNameBytes);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileNameInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < FixedBodyLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete FILE_NAME_INFORMATION structure.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            uint fileNameLength = reader.ReadUInt32();

            if ((fileNameLength % 2) != 0)
            {
                throw new ProtocolEncodingException("FILE_NAME_INFORMATION contains an invalid UTF-16 file-name length.");
            }

            if (fileNameLength > Int32.MaxValue || FixedBodyLength + fileNameLength != buffer.Length)
            {
                throw new ProtocolEncodingException("FILE_NAME_INFORMATION length exceeds the available payload.");
            }

            return new FileNameInformation
            {
                FileName = Encoding.Unicode.GetString(buffer.Slice(FixedBodyLength, checked((int)fileNameLength)).ToArray())
            };
        }

        private string _FileName = string.Empty;
    }
}
