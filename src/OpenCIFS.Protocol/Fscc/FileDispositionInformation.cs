namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// FILE_DISPOSITION_INFORMATION payload.
    /// </summary>
    public sealed class FileDispositionInformation
    {
        private const int StructureLength = 1;

        /// <summary>
        /// Whether the file should be delete-pending.
        /// </summary>
        public bool DeletePending { get; set; }

        /// <summary>
        /// Serialize the structure to bytes.
        /// </summary>
        /// <returns>Encoded bytes.</returns>
        public byte[] ToByteArray()
        {
            return new byte[] { DeletePending ? (byte)1 : (byte)0 };
        }

        /// <summary>
        /// Parse the structure from bytes.
        /// </summary>
        /// <param name="buffer">Encoded bytes.</param>
        /// <returns>Parsed structure.</returns>
        public static FileDispositionInformation ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length != StructureLength)
            {
                throw new ProtocolEncodingException("FILE_DISPOSITION_INFORMATION must be exactly 1 byte.");
            }

            byte value = buffer.Span[0];

            if (value > 1)
            {
                throw new ProtocolEncodingException("FILE_DISPOSITION_INFORMATION contains an invalid delete-pending value.");
            }

            return new FileDispositionInformation
            {
                DeletePending = value != 0
            };
        }
    }
}
