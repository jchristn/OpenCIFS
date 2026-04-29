namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 lease-break acknowledgments.
    /// </summary>
    public static class Smb2LeaseBreakAcknowledgmentValidator
    {
        /// <summary>
        /// Validate a lease-break acknowledgment.
        /// </summary>
        /// <param name="acknowledgment">Acknowledgment to validate.</param>
        public static void Validate(Smb2LeaseBreakAcknowledgment acknowledgment)
        {
            if (acknowledgment == null)
            {
                throw new ProtocolValidationException("The SMB2 lease-break acknowledgment cannot be null.", nameof(acknowledgment));
            }

            if (acknowledgment.LeaseKey.Length != 16)
            {
                throw new ProtocolValidationException("The SMB2 lease-break acknowledgment must contain a 16-byte lease key.", nameof(acknowledgment));
            }

            if ((acknowledgment.LeaseState & ~(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break acknowledgment contains unsupported lease-state bits.", nameof(acknowledgment));
            }

            if (acknowledgment.LeaseDuration != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break acknowledgment lease duration must be zero for the current SMB 2.1 slice.", nameof(acknowledgment));
            }
        }
    }
}
