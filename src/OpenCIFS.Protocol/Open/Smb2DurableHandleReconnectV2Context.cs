namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle reconnect v2 create-context helper for SMB 3.x.
    /// </summary>
    public sealed class Smb2DurableHandleReconnectV2Context
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x44, 0x48, 0x32, 0x43 };

        /// <summary>
        /// Persistent file identifier.
        /// </summary>
        public ulong PersistentFileId { get; set; }

        /// <summary>
        /// Volatile file identifier.
        /// </summary>
        public ulong VolatileFileId { get; set; }

        /// <summary>
        /// Create GUID from the original durable-handle request v2.
        /// </summary>
        public Guid CreateGuid { get; set; }

        /// <summary>
        /// Durable-handle flags for the reconnect request.
        /// </summary>
        public Smb2DurableHandleFlags Flags { get; set; }

        /// <summary>
        /// Durable-handle reconnect v2 context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Create a generic create-context entry from the durable reconnect v2 data.
        /// </summary>
        /// <returns>Create-context entry.</returns>
        public Smb2CreateContext ToCreateContext()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt64(PersistentFileId);
            writer.WriteUInt64(VolatileFileId);
            writer.WriteGuid(CreateGuid);
            writer.WriteUInt32((uint)Flags);
            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = writer.ToArray()
            };
        }

        /// <summary>
        /// Determine whether a generic context is a durable-handle reconnect v2 entry.
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
        /// Parse a durable reconnect v2 context from a generic create-context entry.
        /// </summary>
        /// <param name="context">Context to parse.</param>
        /// <returns>Parsed durable reconnect v2 context.</returns>
        public static Smb2DurableHandleReconnectV2Context ReadFrom(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolEncodingException("The SMB2 create context is not a durable-handle reconnect v2 entry.");
            }

            if (context.Data.Length != 36)
            {
                throw new ProtocolEncodingException("The SMB2 durable-handle reconnect v2 context must contain a 36-byte payload.");
            }

            LittleEndianReader reader = new LittleEndianReader(context.Data);
            Smb2DurableHandleReconnectV2Context reconnectContext = new Smb2DurableHandleReconnectV2Context
            {
                PersistentFileId = reader.ReadUInt64(),
                VolatileFileId = reader.ReadUInt64(),
                CreateGuid = reader.ReadGuid(),
                Flags = (Smb2DurableHandleFlags)reader.ReadUInt32()
            };
            Validate(reconnectContext);
            return reconnectContext;
        }

        /// <summary>
        /// Validate a parsed durable reconnect v2 context.
        /// </summary>
        /// <param name="context">Context to validate.</param>
        public static void Validate(Smb2DurableHandleReconnectV2Context context)
        {
            if (context == null)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle reconnect v2 context cannot be null.", nameof(context));
            }

            if (context.PersistentFileId == 0 && context.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle reconnect v2 context requires a non-zero file identifier.", nameof(context));
            }

            if ((context.Flags & ~Smb2DurableHandleFlags.Persistent) != 0)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle reconnect v2 context contains unsupported flags.", nameof(context));
            }

            if (context.CreateGuid == Guid.Empty)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle reconnect v2 context requires a non-empty create GUID.", nameof(context));
            }
        }
    }
}
