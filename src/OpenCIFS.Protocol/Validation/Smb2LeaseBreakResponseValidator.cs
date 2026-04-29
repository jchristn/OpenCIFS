namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 lease-break responses.
    /// </summary>
    public static class Smb2LeaseBreakResponseValidator
    {
        /// <summary>
        /// Validate a lease-break response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2LeaseBreakResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 lease-break response cannot be null.", nameof(response));
            }

            if (response.LeaseKey.Length != 16)
            {
                throw new ProtocolValidationException("The SMB2 lease-break response must contain a 16-byte lease key.", nameof(response));
            }

            if ((response.LeaseState & ~(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break response contains unsupported lease-state bits.", nameof(response));
            }

            if (response.LeaseDuration != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break response lease duration must be zero for the current SMB 2.1 slice.", nameof(response));
            }
        }
    }
}
