namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Codec for the SMB 3.1.1 negotiate context list area.
    /// </summary>
    /// <remarks>
    /// Each entry is the 8-byte <see cref="Smb2NegotiateContextHeader" /> followed by the typed payload, and entries
    /// are 8-byte aligned. The final entry has no required trailing padding.
    /// </remarks>
    public static class Smb2NegotiateContextList
    {
        private const int ContextHeaderLength = 8;

        /// <summary>
        /// Serialize a list of typed negotiate context entries.
        /// </summary>
        /// <param name="entries">Context entries to serialize.</param>
        /// <returns>Serialized bytes.</returns>
        public static byte[] Encode(IReadOnlyList<Smb2NegotiateContextEntry> entries)
        {
            if (entries == null)
            {
                throw new ArgumentNullException(nameof(entries), "Entries cannot be null.");
            }

            LittleEndianWriter writer = new LittleEndianWriter();

            for (int index = 0; index < entries.Count; index++)
            {
                Smb2NegotiateContextEntry entry = entries[index];

                if (entry == null)
                {
                    throw new ArgumentNullException(nameof(entries), "Entries cannot contain null elements.");
                }

                if (entry.Payload.Length > UInt16.MaxValue)
                {
                    throw new ArgumentOutOfRangeException(nameof(entries), "Negotiate context payload exceeds the 16-bit length field.");
                }

                Smb2NegotiateContextHeader header = new Smb2NegotiateContextHeader
                {
                    ContextType = entry.ContextType,
                    DataLength = (ushort)entry.Payload.Length,
                    Reserved = 0
                };
                writer.WriteBytes(header.ToByteArray());
                writer.WriteBytes(entry.Payload);

                bool isLastEntry = index == entries.Count - 1;

                if (!isLastEntry)
                {
                    int paddingLength = AlignToEight(writer.Length) - writer.Length;

                    for (int padIndex = 0; padIndex < paddingLength; padIndex++)
                    {
                        writer.WriteByte(0);
                    }
                }
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse a list of typed negotiate context entries.
        /// </summary>
        /// <param name="buffer">Serialized context-list bytes.</param>
        /// <param name="entryCount">Declared context-entry count.</param>
        /// <returns>Parsed entries.</returns>
        public static Smb2NegotiateContextEntry[] Decode(ReadOnlyMemory<byte> buffer, int entryCount)
        {
            if (entryCount < 0)
            {
                throw new ArgumentOutOfRangeException(nameof(entryCount), "EntryCount cannot be negative.");
            }

            if (entryCount == 0)
            {
                return Array.Empty<Smb2NegotiateContextEntry>();
            }

            Smb2NegotiateContextEntry[] entries = new Smb2NegotiateContextEntry[entryCount];
            int offset = 0;

            for (int index = 0; index < entryCount; index++)
            {
                if (offset + ContextHeaderLength > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB 3.1.1 negotiate context list is truncated.");
                }

                Smb2NegotiateContextHeader header = Smb2NegotiateContextHeader.ReadFrom(buffer.Slice(offset, ContextHeaderLength));
                int payloadStart = offset + ContextHeaderLength;
                int payloadEnd = payloadStart + header.DataLength;

                if (payloadEnd > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB 3.1.1 negotiate context payload is truncated.");
                }

                entries[index] = new Smb2NegotiateContextEntry
                {
                    ContextType = header.ContextType,
                    Payload = buffer.Slice(payloadStart, header.DataLength).ToArray()
                };

                bool isLastEntry = index == entryCount - 1;
                offset = isLastEntry ? payloadEnd : AlignToEight(payloadEnd);
            }

            return entries;
        }

        private static int AlignToEight(int value)
        {
            int remainder = value % 8;
            return remainder == 0
                ? value
                : value + (8 - remainder);
        }
    }
}
