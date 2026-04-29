namespace OpenCIFS.Transport
{
    using System.Buffers;
    using System.IO.Pipelines;

    /// <summary>
    /// Encodes and decodes framed transport payloads.
    /// </summary>
    public interface IFrameProtocol
    {
        /// <summary>
        /// Try to decode a complete frame from a read buffer.
        /// </summary>
        /// <param name="buffer">Read buffer.</param>
        /// <param name="payload">Decoded payload bytes when successful.</param>
        /// <param name="bytesConsumed">Consumed byte count when successful.</param>
        /// <returns><c>true</c> if a full frame was decoded.</returns>
        bool TryReadFrame(ReadOnlySequence<byte> buffer, out byte[]? payload, out long bytesConsumed);

        /// <summary>
        /// Write a framed payload to an outbound pipe.
        /// </summary>
        /// <param name="writer">Pipe writer.</param>
        /// <param name="payload">Payload bytes.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        ValueTask WriteFrameAsync(PipeWriter writer, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default);
    }
}

