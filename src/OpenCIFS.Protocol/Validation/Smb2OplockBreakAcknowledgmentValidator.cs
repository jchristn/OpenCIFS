namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 oplock-break acknowledgments.
    /// </summary>
    public static class Smb2OplockBreakAcknowledgmentValidator
    {
        /// <summary>
        /// Validate an oplock-break acknowledgment.
        /// </summary>
        /// <param name="acknowledgment">Acknowledgment to validate.</param>
        public static void Validate(Smb2OplockBreakAcknowledgment acknowledgment)
        {
            if (acknowledgment == null)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break acknowledgment cannot be null.", nameof(acknowledgment));
            }

            if (!Enum.IsDefined(typeof(Smb2OplockLevel), acknowledgment.OplockLevel) ||
                acknowledgment.OplockLevel == Smb2OplockLevel.Batch ||
                acknowledgment.OplockLevel == Smb2OplockLevel.Lease)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break acknowledgment oplock level is not valid for the current SMB 2.0.2 slice.", nameof(acknowledgment));
            }

            if (acknowledgment.PersistentFileId == 0 && acknowledgment.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break acknowledgment file identifier must be non-zero.", nameof(acknowledgment));
            }
        }
    }
}
