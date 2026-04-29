namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 negotiate context header.
    /// </summary>
    public sealed class Smb2NegotiateContextHeader
    {
        /// <summary>
        /// Context type.
        /// </summary>
        public Smb2NegotiateContextType ContextType { get; set; } = Smb2NegotiateContextType.PreauthIntegrityCapabilities;

        /// <summary>
        /// Length of the context payload.
        /// </summary>
        public ushort DataLength { get; set; } = 0;

        /// <summary>
        /// Reserved field.
        /// </summary>
        public uint Reserved { get; set; } = 0;

        /// <summary>
        /// Serialize the header.
        /// </summary>
        /// <returns>Header bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16((ushort)ContextType);
            writer.WriteUInt16(DataLength);
            writer.WriteUInt32(Reserved);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the header from a binary buffer.
        /// </summary>
        /// <param name="buffer">Header bytes.</param>
        /// <returns>Parsed header.</returns>
        public static Smb2NegotiateContextHeader ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 8)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 negotiate context header.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            Smb2NegotiateContextHeader header = new Smb2NegotiateContextHeader
            {
                ContextType = (Smb2NegotiateContextType)reader.ReadUInt16(),
                DataLength = reader.ReadUInt16(),
                Reserved = reader.ReadUInt32()
            };

            return header;
        }
    }
}
