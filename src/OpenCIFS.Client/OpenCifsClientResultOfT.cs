namespace OpenCIFS.Client
{
    using System;

    /// <summary>
    /// Non-throwing result envelope for primary OpenCIFS client operations that return a value.
    /// </summary>
    /// <typeparam name="T">Returned value type.</typeparam>
    public sealed class OpenCifsClientResult<T> : OpenCifsClientResult
    {
        private OpenCifsClientResult(T value)
            : base(null)
        {
            Value = value;
        }

        private OpenCifsClientResult(OpenCifsClientException exception)
            : base(exception)
        {
            Value = default;
        }

        /// <summary>
        /// Returned value for a successful operation.
        /// </summary>
        public T? Value { get; }

        /// <summary>
        /// Rethrow the original typed client exception if the operation did not succeed and return the successful value otherwise.
        /// </summary>
        /// <returns>Successful operation value.</returns>
        public T GetValueOrThrow()
        {
            EnsureSuccess();
            return Value!;
        }

        /// <summary>
        /// Create a successful non-throwing result.
        /// </summary>
        /// <param name="value">Successful value.</param>
        /// <returns>Successful result.</returns>
        public static OpenCifsClientResult<T> Success(T value)
        {
            return new OpenCifsClientResult<T>(value);
        }

        /// <summary>
        /// Create a failed non-throwing result.
        /// </summary>
        /// <param name="exception">Typed client failure.</param>
        /// <returns>Failed result.</returns>
        public new static OpenCifsClientResult<T> Failure(OpenCifsClientException exception)
        {
            if (exception == null)
            {
                throw new ArgumentNullException(nameof(exception), "Exception cannot be null.");
            }

            return new OpenCifsClientResult<T>(exception);
        }
    }
}
