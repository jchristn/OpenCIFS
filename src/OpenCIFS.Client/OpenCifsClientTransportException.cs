namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Exception raised when the direct-TCP transport to the server cannot be established or is lost: connection refused,
    /// connect timeout, peer close, connection reset, end of stream, or a failed write.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The original failure is preserved as <see cref="Exception.InnerException"/> (for example a
    /// <see cref="System.Net.Sockets.SocketException"/>, <see cref="System.IO.IOException"/>, or channel-closed exception from
    /// the framing layer). A connect that exceeds the configured connect timeout raises this exception with
    /// <see cref="IsTimeout"/> set and a <see cref="TimeoutException"/> as the inner exception;
    /// <see cref="OperationCanceledException"/> is reserved for cancellation of the caller's own token.
    /// </para>
    /// <para>
    /// Once the transport is lost the connection is torn down: <c>IsConnected</c> and <c>IsAuthenticated</c> report
    /// <c>false</c>, every tracked tree and open handle is invalidated, and later operations on the same client fail with
    /// this exception until a new connection is established. Create a new client (or call <c>ConnectAsync</c> again) to
    /// recover. The <see cref="OpenCifsClientException.Category"/> is always <see cref="OpenCifsErrorCategory.IoError"/>.
    /// </para>
    /// </remarks>
    public sealed class OpenCifsClientTransportException : OpenCifsClientException
    {
        /// <summary>
        /// Initialize a transport exception.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Underlying transport failure.</param>
        public OpenCifsClientTransportException(string message, Exception? innerException)
            : this(message, innerException, isTimeout: false)
        {
        }

        /// <summary>
        /// Initialize a transport exception that may represent a timeout.
        /// </summary>
        /// <param name="message">Failure message.</param>
        /// <param name="innerException">Underlying transport failure.</param>
        /// <param name="isTimeout">Whether the failure was a timeout rather than an error reported by the network stack.</param>
        public OpenCifsClientTransportException(string message, Exception? innerException, bool isTimeout)
            : base(message, OpenCifsErrorCategory.IoError, innerException)
        {
            IsTimeout = isTimeout;
        }

        /// <summary>
        /// Whether the failure was a timeout (the inner exception is then a <see cref="TimeoutException"/>).
        /// </summary>
        public bool IsTimeout { get; }
    }
}
