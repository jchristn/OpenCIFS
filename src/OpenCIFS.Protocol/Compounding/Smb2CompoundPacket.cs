namespace OpenCIFS.Protocol
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// A series of SMB2 messages compounded into a single packet.
    /// </summary>
    public sealed class Smb2CompoundPacket
    {
        /// <summary>
        /// Initialize a compound packet from one or more entries.
        /// </summary>
        /// <param name="entries">Entries in wire order.</param>
        /// <param name="payloadsIncludeCompoundPadding">Whether the supplied payloads already contain any required compound alignment padding for non-final entries.</param>
        public Smb2CompoundPacket(IReadOnlyList<Smb2CompoundPacketEntry> entries, bool payloadsIncludeCompoundPadding = false)
        {
            if (entries == null)
            {
                throw new ArgumentNullException(nameof(entries), "Entries cannot be null.");
            }

            if (entries.Count == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(entries), "At least one compound entry is required.");
            }

            List<Smb2CompoundPacketEntry> normalizedEntries = new List<Smb2CompoundPacketEntry>(entries.Count);

            for (int index = 0; index < entries.Count; index++)
            {
                Smb2CompoundPacketEntry entry = entries[index] ?? throw new ArgumentNullException(nameof(entries), "Compound entries cannot contain null values.");
                bool isLastEntry = index == entries.Count - 1;
                byte[] normalizedPayload = NormalizePayload(entry.Payload, isLastEntry, payloadsIncludeCompoundPadding);
                uint nextCommand = isLastEntry
                    ? 0U
                    : checked((uint)(ProtocolConstants.Smb2HeaderLength + normalizedPayload.Length));
                Smb2Header normalizedHeader = CloneHeader(entry.Header, nextCommand);
                Smb2HeaderValidator.Validate(normalizedHeader);
                normalizedEntries.Add(new Smb2CompoundPacketEntry(normalizedHeader, normalizedPayload));
            }

            Entries = normalizedEntries.AsReadOnly();
        }

        /// <summary>
        /// Entries in wire order.
        /// </summary>
        public IReadOnlyList<Smb2CompoundPacketEntry> Entries { get; }

        /// <summary>
        /// Serialize the compounded packet to wire format.
        /// </summary>
        /// <returns>Encoded packet bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();

            for (int index = 0; index < Entries.Count; index++)
            {
                Smb2CompoundPacketEntry entry = Entries[index];
                writer.WriteBytes(entry.Header.ToByteArray());
                writer.WriteBytes(entry.Payload);
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse a compounded packet from wire format.
        /// </summary>
        /// <param name="buffer">Packet bytes.</param>
        /// <returns>Parsed compound packet.</returns>
        public static Smb2CompoundPacket ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < ProtocolConstants.Smb2HeaderLength)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete SMB2 compounded packet.");
            }

            List<Smb2CompoundPacketEntry> entries = new List<Smb2CompoundPacketEntry>();
            int offset = 0;

            while (offset < buffer.Length)
            {
                if ((offset % 8) != 0)
                {
                    throw new ProtocolEncodingException("Each SMB2 compound entry must begin on an 8-byte boundary.");
                }

                if (buffer.Length - offset < ProtocolConstants.Smb2HeaderLength)
                {
                    throw new ProtocolEncodingException("The compounded packet ends with a truncated SMB2 header.");
                }

                ReadOnlyMemory<byte> headerBuffer = buffer.Slice(offset, ProtocolConstants.Smb2HeaderLength);
                Smb2Header header = Smb2Header.ReadFrom(headerBuffer);
                Smb2HeaderValidator.Validate(header);
                int entryLength = header.NextCommand == 0
                    ? buffer.Length - offset
                    : checked((int)header.NextCommand);

                if (entryLength < ProtocolConstants.Smb2HeaderLength)
                {
                    throw new ProtocolEncodingException("The SMB2 compounded entry length is smaller than the header length.");
                }

                if (offset + entryLength > buffer.Length)
                {
                    throw new ProtocolEncodingException("The SMB2 compounded entry exceeds the available packet length.");
                }

                byte[] payload = buffer.Slice(offset + ProtocolConstants.Smb2HeaderLength, entryLength - ProtocolConstants.Smb2HeaderLength).ToArray();
                entries.Add(new Smb2CompoundPacketEntry(header, payload));

                if (header.NextCommand == 0)
                {
                    offset = buffer.Length;
                    break;
                }

                offset += entryLength;
            }

            if (offset != buffer.Length)
            {
                throw new ProtocolEncodingException("The compounded packet did not terminate cleanly.");
            }

            return new Smb2CompoundPacket(entries, payloadsIncludeCompoundPadding: true);
        }

        private static Smb2Header CloneHeader(Smb2Header header, uint nextCommand)
        {
            return new Smb2Header
            {
                CreditCharge = header.CreditCharge,
                Status = header.Status,
                Command = header.Command,
                CreditRequest = header.CreditRequest,
                Flags = header.Flags,
                NextCommand = nextCommand,
                MessageId = header.MessageId,
                ProcessId = header.ProcessId,
                TreeId = header.TreeId,
                AsyncId = header.AsyncId,
                SessionId = header.SessionId,
                Signature = (byte[])header.Signature.Clone()
            };
        }

        private static byte[] NormalizePayload(byte[] payload, bool isLastEntry, bool payloadsIncludeCompoundPadding)
        {
            byte[] clonedPayload = (byte[])payload.Clone();

            if (isLastEntry)
            {
                return clonedPayload;
            }

            if (payloadsIncludeCompoundPadding)
            {
                if (((ProtocolConstants.Smb2HeaderLength + clonedPayload.Length) % 8) != 0)
                {
                    throw new ProtocolValidationException("A non-final SMB2 compound entry must already be 8-byte aligned when payload padding is preserved.", nameof(payload));
                }

                return clonedPayload;
            }

            int paddingLength = GetEightBytePadding(ProtocolConstants.Smb2HeaderLength + clonedPayload.Length);

            if (paddingLength == 0)
            {
                return clonedPayload;
            }

            byte[] paddedPayload = new byte[clonedPayload.Length + paddingLength];
            Array.Copy(clonedPayload, paddedPayload, clonedPayload.Length);
            return paddedPayload;
        }

        private static int GetEightBytePadding(int absoluteOffset)
        {
            int remainder = absoluteOffset % 8;
            return remainder == 0 ? 0 : 8 - remainder;
        }
    }
}
