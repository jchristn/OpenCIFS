namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Wraps a server response body with the NTSTATUS value returned by the host.
    /// </summary>
    /// <typeparam name="TResponse">Response-body type.</typeparam>
    public sealed class OpenCifsServerOperationResult<TResponse>
        where TResponse : class
    {
        /// <summary>
        /// Response NTSTATUS.
        /// </summary>
        public NtStatus Status { get; set; } = NtStatus.Success;

        /// <summary>
        /// Response body.
        /// </summary>
        public TResponse Response
        {
            get
            {
                return _Response;
            }
            set
            {
                _Response = value ?? throw new ArgumentNullException(nameof(Response), "Response cannot be null.");
            }
        }

        private TResponse _Response = null!;
    }
}
