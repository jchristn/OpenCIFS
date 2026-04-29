namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Tracks SMB session lifecycle state.
    /// </summary>
    public sealed class SessionState : DisposableStateBase
    {
        /// <summary>
        /// Session identifier.
        /// </summary>
        public ulong SessionId { get; private set; } = 0;

        /// <summary>
        /// Whether the session has authenticated.
        /// </summary>
        public bool IsAuthenticated { get; private set; } = false;

        /// <summary>
        /// Bind the state to a session identifier.
        /// </summary>
        /// <param name="sessionId">Session identifier.</param>
        public void Bind(ulong sessionId)
        {
            EnsureNotDisposed();

            if (sessionId == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(sessionId), "Session identifiers must be non-zero.");
            }

            SessionId = sessionId;
        }

        /// <summary>
        /// Mark the session as authenticated.
        /// </summary>
        public void Authenticate()
        {
            EnsureNotDisposed();

            if (SessionId == 0)
            {
                throw new InvalidOperationException("A session identifier must be assigned before authentication.");
            }

            IsAuthenticated = true;
        }
    }
}

