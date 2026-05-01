namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle response v2 create-context helper for SMB 3.x.
    /// </summary>
    public sealed class Smb2DurableHandleResponseV2Context
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x44, 0x48, 0x32, 0x51 };

        /// <summary>
        /// Timeout, in milliseconds, granted for durable reconnect reservation.
        /// </summary>
        public uint Timeout { get; set; }

        /// <summary>
        /// Durable-handle flags granted by the server.
        /// </summary>
        public Smb2DurableHandleFlags Flags { get; set; }

        /// <summary>
        /// Durable-handle response v2 context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Create a generic create-context entry from the durable response v2 data.
        /// </summary>
        /// <returns>Create-context entry.</returns>
        public Smb2CreateContext ToCreateContext()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(Timeout);
            writer.WriteUInt32((uint)Flags);
            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = writer.ToArray()
            };
        }

        /// <summary>
        /// Determine whether a generic context is a durable-handle response v2 entry.
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
        /// Parse a durable response v2 context from a generic create-context entry.
        /// </summary>
        /// <param name="context">Context to parse.</param>
        /// <returns>Parsed durable response v2 context.</returns>
        public static Smb2DurableHandleResponseV2Context ReadFrom(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolEncodingException("The SMB2 create context is not a durable-handle response v2 entry.");
            }

            if (context.Data.Length != 8)
            {
                throw new ProtocolEncodingException("The SMB2 durable-handle response v2 context must contain an 8-byte payload.");
            }

            LittleEndianReader reader = new LittleEndianReader(context.Data);
            Smb2DurableHandleResponseV2Context responseContext = new Smb2DurableHandleResponseV2Context
            {
                Timeout = reader.ReadUInt32(),
                Flags = (Smb2DurableHandleFlags)reader.ReadUInt32()
            };
            Validate(responseContext);
            return responseContext;
        }

        /// <summary>
        /// Validate a parsed durable response v2 context.
        /// </summary>
        /// <param name="context">Context to validate.</param>
        public static void Validate(Smb2DurableHandleResponseV2Context context)
        {
            if (context == null)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle response v2 context cannot be null.", nameof(context));
            }

            if ((context.Flags & ~Smb2DurableHandleFlags.Persistent) != 0)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle response v2 context contains unsupported flags.", nameof(context));
            }
        }
    }
}
