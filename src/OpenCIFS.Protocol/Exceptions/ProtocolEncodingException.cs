namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Represents a binary encoding or decoding failure in SMB/CIFS wire data.
    /// </summary>
    public sealed class ProtocolEncodingException : Exception
    {
        /// <summary>
        /// Initialize the exception.
        /// </summary>
        /// <param name="message">Exception message.</param>
        public ProtocolEncodingException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initialize the exception.
        /// </summary>
        /// <param name="message">Exception message.</param>
        /// <param name="innerException">Inner exception.</param>
        public ProtocolEncodingException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
