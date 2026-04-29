namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle response create-context helper for SMB 2.0.2.
    /// </summary>
    public static class Smb2DurableHandleResponseContext
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x44, 0x48, 0x6E, 0x51 };

        /// <summary>
        /// Durable-handle response context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Create a durable-handle response context.
        /// </summary>
        /// <returns>Generic create-context entry.</returns>
        public static Smb2CreateContext Create()
        {
            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = new byte[8]
            };
        }

        /// <summary>
        /// Determine whether a generic context is a durable-handle response entry.
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
        /// Validate the data payload for a durable-handle response context.
        /// </summary>
        /// <param name="context">Context to validate.</param>
        public static void Validate(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolValidationException("The SMB2 create context is not a durable-handle response.", nameof(context));
            }

            if (context.Data.Length != 8)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle response context must contain an 8-byte reserved payload.", nameof(context));
            }
        }
    }
}
