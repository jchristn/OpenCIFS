namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 durable-handle request create-context helper for SMB 2.0.2.
    /// </summary>
    public static class Smb2DurableHandleRequestContext
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x44, 0x48, 0x6E, 0x51 };

        /// <summary>
        /// Durable-handle request context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Create a durable-handle request context.
        /// </summary>
        /// <returns>Generic create-context entry.</returns>
        public static Smb2CreateContext Create()
        {
            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = new byte[16]
            };
        }

        /// <summary>
        /// Determine whether a generic context is a durable-handle request entry.
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
        /// Validate the data payload for a durable-handle request context.
        /// </summary>
        /// <param name="context">Context to validate.</param>
        public static void Validate(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolValidationException("The SMB2 create context is not a durable-handle request.", nameof(context));
            }

            if (context.Data.Length != 16)
            {
                throw new ProtocolValidationException("The SMB2 durable-handle request context must contain a 16-byte reserved payload.", nameof(context));
            }
        }
    }
}
