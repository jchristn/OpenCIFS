namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Exception raised when the managed OpenCIFS server surface is configured inconsistently.
    /// </summary>
    public sealed class OpenCifsServerConfigurationException : OpenCifsServerException
    {
        /// <summary>
        /// Initialize a server-configuration exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        public OpenCifsServerConfigurationException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initialize a server-configuration exception with an inner exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Inner exception.</param>
        public OpenCifsServerConfigurationException(string message, Exception? innerException)
            : base(message, innerException)
        {
        }
    }
}
