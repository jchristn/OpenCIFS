namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Exception raised when a managed OpenCIFS server operation is invalid for the current runtime state.
    /// </summary>
    public sealed class OpenCifsServerStateException : OpenCifsServerException
    {
        /// <summary>
        /// Initialize a server-state exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        public OpenCifsServerStateException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initialize a server-state exception with an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Inner exception.</param>
        public OpenCifsServerStateException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}
