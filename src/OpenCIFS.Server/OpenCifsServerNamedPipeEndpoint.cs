namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Immutable named-pipe endpoint registration for the OpenCIFS server surface.
    /// </summary>
    public sealed class OpenCifsServerNamedPipeEndpoint
    {
        /// <summary>
        /// Initialize a named-pipe endpoint registration.
        /// </summary>
        /// <param name="pipeName">Named-pipe endpoint name.</param>
        /// <param name="transceiveHandler">Bounded transceive handler.</param>
        public OpenCifsServerNamedPipeEndpoint(string pipeName, Func<OpenCifsServerNamedPipeRequestContext, OpenCifsServerNamedPipeResponse> transceiveHandler)
        {
            if (string.IsNullOrWhiteSpace(pipeName))
            {
                throw new ArgumentNullException(nameof(pipeName), "PipeName cannot be null or whitespace.");
            }

            if (pipeName.IndexOfAny(new[] { '\\', '/' }) >= 0)
            {
                throw new ArgumentException("PipeName must be a single path segment.", nameof(pipeName));
            }

            PipeName = pipeName;
            _TransceiveHandler = transceiveHandler ?? throw new ArgumentNullException(nameof(transceiveHandler), "TransceiveHandler cannot be null.");
        }

        /// <summary>
        /// Named-pipe endpoint name.
        /// </summary>
        public string PipeName { get; }

        internal OpenCifsServerNamedPipeResponse Transceive(OpenCifsServerNamedPipeRequestContext context)
        {
            return _TransceiveHandler(context ?? throw new ArgumentNullException(nameof(context), "Context cannot be null."));
        }

        private readonly Func<OpenCifsServerNamedPipeRequestContext, OpenCifsServerNamedPipeResponse> _TransceiveHandler;
    }
}
