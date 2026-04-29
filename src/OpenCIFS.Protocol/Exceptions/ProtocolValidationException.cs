namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Represents invalid SMB/CIFS protocol state or malformed field values.
    /// </summary>
    public sealed class ProtocolValidationException : ArgumentException
    {
        /// <summary>
        /// Initialize the exception.
        /// </summary>
        /// <param name="message">Exception message.</param>
        public ProtocolValidationException(string message) : base(message)
        {
        }

        /// <summary>
        /// Initialize the exception.
        /// </summary>
        /// <param name="message">Exception message.</param>
        /// <param name="paramName">Parameter or field name.</param>
        public ProtocolValidationException(string message, string paramName) : base(message, paramName)
        {
        }
    }
}

