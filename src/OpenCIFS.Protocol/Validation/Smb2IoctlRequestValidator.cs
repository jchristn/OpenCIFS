namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 IOCTL requests.
    /// </summary>
    public static class Smb2IoctlRequestValidator
    {
        private const Smb2IoctlFlags SupportedFlags = Smb2IoctlFlags.IsFsctl;

        /// <summary>
        /// Validate an IOCTL request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2IoctlRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL request cannot be null.", nameof(request));
            }

            if (request.CtlCode == 0)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL request must specify a non-zero control code.", nameof(request));
            }

            if ((request.Flags & ~SupportedFlags) != 0)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL request contains flags outside the currently supported SMB2 IOCTL flag set.", nameof(request));
            }

            bool wildcardPersistent = request.PersistentFileId == UInt64.MaxValue;
            bool wildcardVolatile = request.VolatileFileId == UInt64.MaxValue;

            if (wildcardPersistent != wildcardVolatile)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL request must use either a complete wildcard file identifier or a concrete file identifier pair.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL request must identify either a concrete file handle or the wildcard file identifier pair.", nameof(request));
            }
        }
    }
}
