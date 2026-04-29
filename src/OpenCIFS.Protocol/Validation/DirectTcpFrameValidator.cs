namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates Direct TCP frame headers.
    /// </summary>
    public static class DirectTcpFrameValidator
    {
        /// <summary>
        /// Validate a Direct TCP frame header.
        /// </summary>
        /// <param name="header">Header to validate.</param>
        public static void Validate(DirectTcpFrameHeader header)
        {
            if (header == null)
            {
                throw new ProtocolValidationException("The Direct TCP header cannot be null.", nameof(header));
            }

            if (header.Length <= 0)
            {
                throw new ProtocolValidationException("Direct TCP frame lengths must be positive.", nameof(header));
            }
        }
    }
}

