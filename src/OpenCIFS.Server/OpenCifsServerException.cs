namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Base exception for managed OpenCIFS server-surface failures.
    /// </summary>
    public abstract class OpenCifsServerException : InvalidOperationException
    {
        /// <summary>
        /// Initialize a server-surface exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        protected OpenCifsServerException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initialize a server-surface exception with an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Inner exception.</param>
        protected OpenCifsServerException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}
