namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Exception raised when a managed OpenCIFS client operation is invalid for the current local lifecycle or handle state.
    /// </summary>
    public sealed class OpenCifsClientStateException : OpenCifsClientException
    {
        /// <summary>
        /// Initialize a client-state exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        public OpenCifsClientStateException(string message)
            : base(message, OpenCifsErrorCategory.Unknown)
        {
        }

        /// <summary>
        /// Initialize a client-state exception with an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Inner exception.</param>
        public OpenCifsClientStateException(string message, Exception? innerException)
            : base(message, OpenCifsErrorCategory.Unknown, innerException)
        {
        }
    }
}
