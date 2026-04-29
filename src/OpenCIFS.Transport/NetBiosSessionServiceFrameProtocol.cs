namespace OpenCIFS.Transport
{
    using System;
    using System.Buffers;
    using System.IO.Pipelines;
    using OpenCIFS.Protocol;

    /// <summary>
    /// NetBIOS session service frame codec for SMB payloads.
    /// </summary>
    public sealed class NetBiosSessionServiceFrameProtocol : IFrameProtocol
    {
        /// <summary>
        /// Default message type for outbound payloads.
        /// </summary>
        public NetBiosSessionMessageType MessageType { get; set; } = NetBiosSessionMessageType.SessionMessage;

        /// <summary>
        /// Maximum permitted frame payload length.
        /// Default value: <c>1048576</c>.
        /// Minimum value: <c>1024</c>.
        /// Maximum value: <c>16777215</c>.
        /// </summary>
        public int MaximumFrameLength
        {
            get
            {
                return _MaximumFrameLength;
            }
            set
            {
                _MaximumFrameLength = Math.Clamp(value, 1024, 0x00FFFFFF);
            }
        }

        /// <summary>
        /// Try to decode a complete frame from a read buffer.
        /// </summary>
        /// <param name="buffer">Read buffer.</param>
        /// <param name="payload">Decoded payload bytes when successful.</param>
        /// <param name="bytesConsumed">Consumed byte count when successful.</param>
        /// <returns><c>true</c> if a full frame was decoded.</returns>
        public bool TryReadFrame(ReadOnlySequence<byte> buffer, out byte[]? payload, out long bytesConsumed)
        {
            payload = null;
            bytesConsumed = 0;

            if (buffer.Length < NetBiosSessionServiceHeader.Size)
            {
                return false;
            }

            NetBiosSessionServiceHeader header = NetBiosSessionServiceHeader.ReadFrom(buffer.Slice(0, NetBiosSessionServiceHeader.Size).ToArray());
            NetBiosSessionServiceValidator.Validate(header);

            if (header.Length > MaximumFrameLength)
            {
                throw new ProtocolValidationException("The NetBIOS session service frame length exceeds the configured maximum.", nameof(buffer));
            }

            long totalLength = NetBiosSessionServiceHeader.Size + header.Length;

            if (buffer.Length < totalLength)
            {
                return false;
            }

            payload = buffer.Slice(NetBiosSessionServiceHeader.Size, header.Length).ToArray();
            bytesConsumed = totalLength;
            return true;
        }

        /// <summary>
        /// Write a framed payload to an outbound pipe.
        /// </summary>
        /// <param name="writer">Pipe writer.</param>
        /// <param name="payload">Payload bytes.</param>
        /// <param name="cancellationToken">Cancellation token.</param>
        /// <returns>Completion task.</returns>
        public ValueTask WriteFrameAsync(PipeWriter writer, ReadOnlyMemory<byte> payload, CancellationToken cancellationToken = default)
        {
            if (payload.Length > MaximumFrameLength)
            {
                throw new ArgumentOutOfRangeException(nameof(payload), "The payload exceeds the configured maximum frame length.");
            }

            NetBiosSessionServiceHeader header = new NetBiosSessionServiceHeader
            {
                MessageType = MessageType,
                Length = payload.Length
            };

            writer.Write(header.ToByteArray());
            writer.Write(payload.Span);
            return ValueTask.CompletedTask;
        }

        private int _MaximumFrameLength = 1024 * 1024;
    }
}
