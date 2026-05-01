namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Base exception for managed OpenCIFS client-surface failures.
    /// </summary>
    public abstract class OpenCifsClientException : InvalidOperationException
    {
        /// <summary>
        /// Initialize a client-surface exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="category">Normalized failure category.</param>
        protected OpenCifsClientException(string message, OpenCifsErrorCategory category)
            : base(message)
        {
            Category = category;
        }

        /// <summary>
        /// Initialize a client-surface exception with an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="category">Normalized failure category.</param>
        /// <param name="innerException">Inner exception.</param>
        protected OpenCifsClientException(string message, OpenCifsErrorCategory category, Exception? innerException)
            : base(message, innerException)
        {
            Category = category;
        }

        /// <summary>
        /// Normalized high-level error category for this failure.
        /// </summary>
        public OpenCifsErrorCategory Category { get; }
    }
}
