namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// One SMB2 message entry within a compounded packet.
    /// </summary>
    public sealed class Smb2CompoundPacketEntry
    {
        /// <summary>
        /// Initialize a compound-packet entry.
        /// </summary>
        /// <param name="header">SMB2 header for the entry.</param>
        /// <param name="payload">Payload bytes that appear between this header and the next header.
        /// When the entry is part of a non-final compounded request or response, these bytes can include compound alignment padding.</param>
        public Smb2CompoundPacketEntry(Smb2Header header, byte[] payload)
        {
            Header = header ?? throw new ArgumentNullException(nameof(header), "Header cannot be null.");
            Payload = payload ?? throw new ArgumentNullException(nameof(payload), "Payload cannot be null.");
        }

        /// <summary>
        /// SMB2 header for the entry.
        /// </summary>
        public Smb2Header Header { get; }

        /// <summary>
        /// Payload bytes that appear between this header and the next header.
        /// </summary>
        public byte[] Payload { get; }
    }
}
