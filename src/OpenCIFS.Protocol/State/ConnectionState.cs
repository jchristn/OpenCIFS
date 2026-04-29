namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Tracks SMB connection lifecycle state.
    /// </summary>
    public sealed class ConnectionState : DisposableStateBase
    {
        /// <summary>
        /// Connection identifier.
        /// </summary>
        public Guid ConnectionId { get; } = Guid.NewGuid();

        /// <summary>
        /// Connection creation time in UTC.
        /// </summary>
        public DateTime CreatedUtc { get; } = DateTime.UtcNow;

        /// <summary>
        /// Negotiated dialect if available.
        /// </summary>
        public SmbDialect? NegotiatedDialect { get; private set; } = null;

        /// <summary>
        /// Credit accounting state.
        /// </summary>
        public CreditState Credits { get; } = new CreditState();

        /// <summary>
        /// Whether negotiate has completed.
        /// </summary>
        public bool IsNegotiated
        {
            get
            {
                return NegotiatedDialect.HasValue;
            }
        }

        /// <summary>
        /// Record the negotiated dialect.
        /// </summary>
        /// <param name="dialect">Negotiated dialect.</param>
        public void Negotiate(SmbDialect dialect)
        {
            EnsureNotDisposed();
            NegotiatedDialect = dialect;
        }

        /// <summary>
        /// Dispose the connection state.
        /// </summary>
        /// <param name="disposing">Whether managed resources are being disposed.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                Credits.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

