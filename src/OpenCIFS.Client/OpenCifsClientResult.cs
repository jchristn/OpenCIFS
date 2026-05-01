namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Non-throwing result envelope for primary OpenCIFS client operations.
    /// </summary>
    public class OpenCifsClientResult
    {
        private protected OpenCifsClientResult(OpenCifsClientException? exception)
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
        /// Typed client failure when the operation did not succeed.
        /// </summary>
        public OpenCifsClientException? Exception { get; }

        /// <summary>
        /// Normalized high-level error category for the failure when available.
        /// </summary>
        public OpenCifsErrorCategory? ErrorCategory
        {
            get
            {
                return Exception?.Category;
            }
        }

        /// <summary>
        /// SMB2 command that failed when the result represents a server-returned status.
        /// </summary>
        public Smb2Command? Command
        {
            get
            {
                return (Exception as OpenCifsStatusException)?.Command;
            }
        }

        /// <summary>
        /// Returned NTSTATUS when the result represents a server-returned SMB failure.
        /// </summary>
        public NtStatus? Status
        {
            get
            {
                return (Exception as OpenCifsStatusException)?.Status;
            }
        }

        /// <summary>
        /// SMB2 error-data bytes when the result represents a server-returned SMB failure.
        /// </summary>
        public ReadOnlyMemory<byte> ErrorData
        {
            get
            {
                return (Exception as OpenCifsStatusException)?.ErrorData ?? ReadOnlyMemory<byte>.Empty;
            }
        }

        /// <summary>
        /// Rethrow the original typed client exception if the operation did not succeed.
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
        public static OpenCifsClientResult Success()
        {
            return new OpenCifsClientResult(null);
        }

        /// <summary>
        /// Create a failed non-throwing result.
        /// </summary>
        /// <param name="exception">Typed client failure.</param>
        /// <returns>Failed result.</returns>
        public static OpenCifsClientResult Failure(OpenCifsClientException exception)
        {
            if (exception == null)
            {
                throw new ArgumentNullException(nameof(exception), "Exception cannot be null.");
            }

            return new OpenCifsClientResult(exception);
        }
    }
}
