namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 logoff requests.
    /// </summary>
    public static class Smb2LogoffRequestValidator
    {
        /// <summary>
        /// Validate a logoff request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2LogoffRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 logoff request cannot be null.", nameof(request));
            }
        }
    }
}
