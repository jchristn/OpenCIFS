namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle request v2 create-context helper for SMB 3.x.
    /// </summary>
    public sealed class Smb2DurableHandleRequestV2Context
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x44, 0x48, 0x32, 0x51 };

        /// <summary>
        /// Timeout, in milliseconds, requested for the durable reconnect reservation.
        /// </summary>
        public uint Timeout { get; set; }

        /// <summary>
        /// Durable-handle flags for the request.
        /// </summary>
        public Smb2DurableHandleFlags Flags { get; set; }

        /// <summary>
        /// Create GUID that identifies the durable open request.
        /// </summary>
        public Guid CreateGuid { get; set; }

        /// <summary>
        /// Durable-handle request v2 context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Convert the durable-handle request v2 data into a generic create-context entry.
        /// </summary>
        /// <returns>Create-context entry.</returns>
        public Smb2CreateContext ToCreateContext()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt32(Timeout);
            writer.WriteUInt32((uint)Flags);
            writer.WriteUInt64(0);
            writer.WriteGuid(CreateGuid);
            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = writer.ToArray()
            };
        }

        /// <summary>
        /// Determine whether a generic context is a durable-handle request v2 entry.
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
        /// Parse a durable-handle request v2 context from a generic create-context entry.
        /// </summary>
        /// <param name="context">Context to parse.</param>
        /// <returns>Parsed durable-handle request v2 context.</returns>
        public static Smb2DurableHandleRequestV2Context ReadFrom(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolEncodingException("The SMB2 create context is not a durable-handle request v2 entry.");
            }

            if (context.Data.Length != 32)
            {
                throw new ProtocolEncodingException("The SMB2 durable-handle request v2 context must contain a 32-byte payload.");
            }

            LittleEndianReader reader = new LittleEndianReader(context.Data);
            Smb2DurableHandleRequestV2Context durableContext = new Smb2DurableHandleRequestV2Context
            {
                Timeout = reader.ReadUInt32(),
                Flags = (Smb2DurableHandleFlags)reader.ReadUInt32()
            };
            reader.ReadUInt64();
            durableContext.CreateGuid = reader.ReadGuid();
            Validate(durableContext);
            return durableContext;
        }

        /// <summary>
        /// Validate a parsed durable-handle request v2 context.
        /// </summary>
        /// <param name="context">Context to validate.</param>
        public static void Validate(Smb2DurableHandleRequestV2Context context)
        {
            if (context == null)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle request v2 context cannot be null.", nameof(context));
            }

            if ((context.Flags & ~Smb2DurableHandleFlags.Persistent) != 0)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle request v2 context contains unsupported flags.", nameof(context));
            }

            if (context.CreateGuid == Guid.Empty)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle request v2 context requires a non-empty create GUID.", nameof(context));
            }
        }
    }
}
