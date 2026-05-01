namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Response returned by a named-pipe endpoint hosted by OpenCIFS.
    /// </summary>
    public sealed class OpenCifsServerNamedPipeResponse
    {
        /// <summary>
        /// Initialize a named-pipe response.
        /// </summary>
        /// <param name="status">SMB status to return from the transceive request.</param>
        /// <param name="outputBuffer">Output buffer payload.</param>
        public OpenCifsServerNamedPipeResponse(NtStatus status, byte[]? outputBuffer = null)
        {
            Status = status;
            OutputBuffer = outputBuffer ?? Array.Empty<byte>();
        }

        /// <summary>
        /// SMB status returned by the transceive operation.
        /// </summary>
        public NtStatus Status { get; }

        /// <summary>
        /// Output buffer payload returned by the named-pipe endpoint.
        /// </summary>
        public byte[] OutputBuffer { get; }

        /// <summary>
        /// Create a successful response with the supplied payload.
        /// </summary>
        /// <param name="outputBuffer">Output buffer payload.</param>
        /// <returns>Successful named-pipe response.</returns>
        public static OpenCifsServerNamedPipeResponse Success(byte[]? outputBuffer = null)
        {
            return new OpenCifsServerNamedPipeResponse(NtStatus.Success, outputBuffer);
        }
    }
}
