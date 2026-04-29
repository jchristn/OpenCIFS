namespace OpenCIFS.Transport
{
    using System;

    /// <summary>
    /// Options for a framed pipe transport connection.
    /// </summary>
    public sealed class FramedPipeConnectionOptions
    {
        /// <summary>
        /// Inbound frame channel capacity.
        /// Default value: <c>64</c>.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>4096</c>.
        /// </summary>
        public int InboundFrameCapacity
        {
            get
            {
                return _InboundFrameCapacity;
            }
            set
            {
                _InboundFrameCapacity = Math.Clamp(value, 1, 4096);
            }
        }

        /// <summary>
        /// Outbound frame channel capacity.
        /// Default value: <c>64</c>.
        /// Minimum value: <c>1</c>.
        /// Maximum value: <c>4096</c>.
        /// </summary>
        public int OutboundFrameCapacity
        {
            get
            {
                return _OutboundFrameCapacity;
            }
            set
            {
                _OutboundFrameCapacity = Math.Clamp(value, 1, 4096);
            }
        }

        private int _InboundFrameCapacity = 64;
        private int _OutboundFrameCapacity = 64;
    }
}

