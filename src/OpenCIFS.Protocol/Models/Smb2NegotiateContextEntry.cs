namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// One typed SMB2 negotiate context with its raw payload bytes.
    /// </summary>
    public sealed class Smb2NegotiateContextEntry
    {
        /// <summary>
        /// Negotiate context type.
        /// </summary>
        public Smb2NegotiateContextType ContextType { get; set; } = Smb2NegotiateContextType.PreauthIntegrityCapabilities;

        /// <summary>
        /// Raw payload bytes for the context.
        /// </summary>
        public byte[] Payload
        {
            get
            {
                return _Payload;
            }
            set
            {
                _Payload = value ?? throw new ArgumentNullException(nameof(Payload), "Payload cannot be null.");
            }
        }

        private byte[] _Payload = Array.Empty<byte>();
    }
}
