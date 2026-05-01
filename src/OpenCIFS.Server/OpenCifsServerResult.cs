namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Non-throwing result envelope for managed OpenCIFS server application operations.
    /// </summary>
    public sealed class OpenCifsServerResult
    {
        private OpenCifsServerResult(OpenCifsServerException? exception)
        {
            Exception = exception;
        }

        /// <summary>
        /// Whether the operation completed successfully.
        /// </summary>
        public bool IsSuccess
        {
            get
            {
                return Exception == null;
            }
        }

        /// <summary>
        /// Typed server failure when the operation did not succeed.
        /// </summary>
        public OpenCifsServerException? Exception { get; }

        /// <summary>
        /// Rethrow the original typed server exception if the operation did not succeed.
        /// </summary>
        public void EnsureSuccess()
        {
            if (Exception != null)
            {
                throw Exception;
            }
        }

        /// <summary>
        /// Create a successful non-throwing result.
        /// </summary>
        /// <returns>Successful result.</returns>
        public static OpenCifsServerResult Success()
        {
            return new OpenCifsServerResult(null);
        }

        /// <summary>
        /// Create a failed non-throwing result.
        /// </summary>
        /// <param name="exception">Typed server failure.</param>
        /// <returns>Failed result.</returns>
        public static OpenCifsServerResult Failure(OpenCifsServerException exception)
        {
            if (exception == null)
            {
                throw new ArgumentNullException(nameof(exception), "Exception cannot be null.");
            }

            return new OpenCifsServerResult(exception);
        }
    }
}
