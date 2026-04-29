namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle reconnect create-context helper for SMB 2.0.2.
    /// </summary>
    public sealed class Smb2DurableHandleReconnectContext
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x44, 0x48, 0x6E, 0x43 };

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Durable-handle reconnect context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Create a generic create-context entry from the durable reconnect data.
        /// </summary>
        /// <returns>Create-context entry.</returns>
        public Smb2CreateContext ToCreateContext()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = writer.ToArray()
            };
        }

        /// <summary>
        /// Determine whether a generic context is a durable-handle reconnect entry.
        /// </summary>
        /// <param name="context">Context to inspect.</param>
        /// <returns><c>true</c> when the name matches.</returns>
        public static bool IsMatch(Smb2CreateContext context)
        {
            return context != null &&
                context.Name.Length == ContextNameValue.Length &&
                context.Name.AsSpan().SequenceEqual(ContextNameValue);
        }

        /// <summary>
        /// Parse a durable reconnect context from a generic create-context entry.
        /// </summary>
        /// <param name="context">Context to parse.</param>
        /// <returns>Parsed durable reconnect context.</returns>
        public static Smb2DurableHandleReconnectContext ReadFrom(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolEncodingException("The SMB2 create context is not a durable-handle reconnect entry.");
            }

            if (context.Data.Length != 16)
            {
                throw new ProtocolEncodingException("The SMB2 durable-handle reconnect context must contain a 16-byte SMB2_FILEID payload.");
            }

            LittleEndianReader reader = new LittleEndianReader(context.Data);
            return new Smb2DurableHandleReconnectContext
            {
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64()
            };
        }
    }
}
