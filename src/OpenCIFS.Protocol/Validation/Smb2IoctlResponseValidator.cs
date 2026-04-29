namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 IOCTL responses.
    /// </summary>
    public static class Smb2IoctlResponseValidator
    {
        /// <summary>
        /// Validate an IOCTL response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2IoctlResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL response cannot be null.", nameof(response));
            }

            if (response.CtlCode == 0)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL response must specify a non-zero control code.", nameof(response));
            }

            bool wildcardPersistent = response.PersistentFileId == UInt64.MaxValue;
            bool wildcardVolatile = response.VolatileFileId == UInt64.MaxValue;

            if (wildcardPersistent != wildcardVolatile)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL response must use either a complete wildcard file identifier or a concrete file identifier pair.", nameof(response));
            }

            if (response.PersistentFileId == 0 && response.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL response must identify either a concrete file handle or the wildcard file identifier pair.", nameof(response));
            }

            if (response.Flags != 0)
            {
                throw new ProtocolValidationException("The SMB2 IOCTL response flags field must remain zero for the current SMB 2.0.2 slice.", nameof(response));
            }
        }
    }
}
