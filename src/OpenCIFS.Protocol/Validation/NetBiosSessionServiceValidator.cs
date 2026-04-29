namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates NetBIOS session service headers.
    /// </summary>
    public static class NetBiosSessionServiceValidator
    {
        /// <summary>
        /// Validate a NetBIOS session service header.
        /// </summary>
        /// <param name="header">Header to validate.</param>
        public static void Validate(NetBiosSessionServiceHeader header)
        {
            if (header == null)
            {
                throw new ProtocolValidationException("The NetBIOS session service header cannot be null.", nameof(header));
            }

            if (!Enum.IsDefined(typeof(NetBiosSessionMessageType), header.MessageType))
            {
                throw new ProtocolValidationException("The NetBIOS session service message type is not recognized.", nameof(header));
            }

            if (header.Length < 0 || header.Length > 0x00FFFFFF)
            {
                throw new ProtocolValidationException("The NetBIOS session service payload length must fit within 24 bits.", nameof(header));
            }
        }
    }
}

