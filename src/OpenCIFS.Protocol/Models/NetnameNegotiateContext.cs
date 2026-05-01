namespace OpenCIFS.Protocol
{
    using System;
    using System.Text;

    /// <summary>
    /// SMB 3.1.1 NETNAME negotiate context.
    /// </summary>
    public sealed class NetnameNegotiateContext
    {
        /// <summary>
        /// Server name advertised by the client.
        /// </summary>
        public string ServerName
        {
            get
            {
                return _ServerName;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(ServerName), "ServerName cannot be null.");
                }

                _ServerName = value;
            }
        }

        /// <summary>
        /// Serialize the context payload as UTF-16 LE without a terminator.
        /// </summary>
        /// <returns>Payload bytes.</returns>
        public byte[] ToByteArray()
        {
            return Encoding.Unicode.GetBytes(ServerName);
        }

        /// <summary>
        /// Parse the context payload from a binary buffer.
        /// </summary>
        /// <param name="buffer">Payload bytes.</param>
        /// <returns>Parsed context.</returns>
        public static NetnameNegotiateContext ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if ((buffer.Length & 1) != 0)
            {
                throw new ProtocolEncodingException("The NETNAME negotiate context payload must be UTF-16 LE encoded.");
            }

            return new NetnameNegotiateContext
            {
                ServerName = Encoding.Unicode.GetString(buffer.Span)
            };
        }

        private string _ServerName = string.Empty;
    }
}
