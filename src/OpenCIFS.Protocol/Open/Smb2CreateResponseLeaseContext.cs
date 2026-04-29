namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 create response lease create-context helper for SMB 2.1.
    /// </summary>
    public sealed class Smb2CreateResponseLeaseContext
    {
        private static readonly byte[] ContextNameValue = new byte[] { 0x52, 0x71, 0x4C, 0x73 };

        /// <summary>
        /// Create-context name bytes.
        /// </summary>
        public static ReadOnlyMemory<byte> ContextName
        {
            get
            {
                return ContextNameValue;
            }
        }

        /// <summary>
        /// Lease key bytes.
        /// </summary>
        public byte[] LeaseKey
        {
            get
            {
                return _LeaseKey;
            }
            set
            {
                _LeaseKey = value ?? throw new ArgumentNullException(nameof(LeaseKey), "LeaseKey cannot be null.");
            }
        }

        /// <summary>
        /// Granted lease state.
        /// </summary>
        public Smb2LeaseState LeaseState { get; set; } = Smb2LeaseState.None;

        /// <summary>
        /// Lease response flags.
        /// </summary>
        public Smb2LeaseFlags LeaseFlags { get; set; } = Smb2LeaseFlags.None;

        /// <summary>
        /// Reserved lease duration field. Must be zero for SMB 2.1.
        /// </summary>
        public ulong LeaseDuration { get; set; }

        /// <summary>
        /// Determine whether a generic create context is an SMB 2.1 lease response context.
        /// </summary>
        /// <param name="context">Context to inspect.</param>
        /// <returns><c>true</c> when the context name and payload length match.</returns>
        public static bool IsMatch(Smb2CreateContext context)
        {
            return context != null &&
                context.Name.Length == ContextNameValue.Length &&
                context.Name.AsSpan().SequenceEqual(ContextNameValue) &&
                context.Data.Length == 32;
        }

        /// <summary>
        /// Determine whether a generic create context uses the lease context name.
        /// </summary>
        /// <param name="context">Context to inspect.</param>
        /// <returns><c>true</c> when the name matches the lease context value.</returns>
        public static bool HasLeaseContextName(Smb2CreateContext context)
        {
            return context != null &&
                context.Name.Length == ContextNameValue.Length &&
                context.Name.AsSpan().SequenceEqual(ContextNameValue);
        }

        /// <summary>
        /// Convert the typed lease response context to a generic SMB2 create context.
        /// </summary>
        /// <returns>Create-context entry.</returns>
        public Smb2CreateContext ToCreateContext()
        {
            Validate(this);

            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteBytes(LeaseKey);
            writer.WriteUInt32((uint)LeaseState);
            writer.WriteUInt32((uint)LeaseFlags);
            writer.WriteUInt64(LeaseDuration);

            return new Smb2CreateContext
            {
                Name = (byte[])ContextNameValue.Clone(),
                Data = writer.ToArray()
            };
        }

        /// <summary>
        /// Parse a typed SMB 2.1 lease response context from a generic create-context entry.
        /// </summary>
        /// <param name="context">Create-context entry.</param>
        /// <returns>Parsed lease response context.</returns>
        public static Smb2CreateResponseLeaseContext ReadFrom(Smb2CreateContext context)
        {
            if (!IsMatch(context))
            {
                throw new ProtocolValidationException("The SMB2 create context is not an SMB 2.1 lease response context.", nameof(context));
            }

            LittleEndianReader reader = new LittleEndianReader(context.Data);
            Smb2CreateResponseLeaseContext leaseContext = new Smb2CreateResponseLeaseContext
            {
                LeaseKey = reader.ReadBytes(16),
                LeaseState = (Smb2LeaseState)reader.ReadUInt32(),
                LeaseFlags = (Smb2LeaseFlags)reader.ReadUInt32(),
                LeaseDuration = reader.ReadUInt64()
            };
            Validate(leaseContext);
            return leaseContext;
        }

        /// <summary>
        /// Validate a typed SMB 2.1 lease response context.
        /// </summary>
        /// <param name="context">Context to validate.</param>
        public static void Validate(Smb2CreateResponseLeaseContext context)
        {
            if (context == null)
            {
                throw new ProtocolValidationException("The SMB2 create response lease context cannot be null.", nameof(context));
            }

            if (context.LeaseKey.Length != 16)
            {
                throw new ProtocolValidationException("The SMB2 create response lease context must contain a 16-byte lease key.", nameof(context));
            }

            if ((context.LeaseState & ~(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 create response lease context contains unsupported lease-state bits.", nameof(context));
            }

            if ((context.LeaseFlags & ~Smb2LeaseFlags.BreakInProgress) != 0)
            {
                throw new ProtocolValidationException("The SMB2 create response lease context contains unsupported lease flags.", nameof(context));
            }

            if (context.LeaseDuration != 0)
            {
                throw new ProtocolValidationException("The SMB2 create response lease duration must be zero for the current SMB 2.1 slice.", nameof(context));
            }
        }

        private byte[] _LeaseKey = new byte[16];
    }
}
