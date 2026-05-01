namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Exception raised when a managed OpenCIFS client operation encounters malformed or unsupported protocol behavior.
    /// </summary>
    public sealed class OpenCifsClientProtocolException : OpenCifsClientException
    {
        /// <summary>
        /// Initialize a protocol exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        public OpenCifsClientProtocolException(string message)
            : this(message, contextName: null, innerException: null)
        {
        }

        /// <summary>
        /// Initialize a protocol exception with a named context parameter.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="contextName">Optional named protocol context.</param>
        public OpenCifsClientProtocolException(string message, string? contextName)
            : this(message, contextName, innerException: null)
        {
        }

        /// <summary>
        /// Initialize a protocol exception with an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Inner exception.</param>
        public OpenCifsClientProtocolException(string message, Exception? innerException)
            : this(message, contextName: null, innerException)
        {
        }

        /// <summary>
        /// Initialize a protocol exception with a named context parameter and an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="contextName">Optional named protocol context.</param>
        /// <param name="innerException">Inner exception.</param>
        public OpenCifsClientProtocolException(string message, string? contextName, Exception? innerException)
            : base(CreateMessage(message, contextName), OpenCifsErrorCategory.ProtocolError, innerException)
        {
            ContextName = contextName ?? string.Empty;
        }

        /// <summary>
        /// Optional named protocol context carried with the failure.
        /// </summary>
        public string ContextName { get; }

        private static string CreateMessage(string message, string? contextName)
        {
            if (string.IsNullOrWhiteSpace(contextName))
            {
                return message;
            }

            return message + " Context=" + contextName + ".";
        }
    }
}
