namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 session-setup requests.
    /// </summary>
    public static class Smb2SessionSetupRequestValidator
    {
        /// <summary>
        /// Validate a session-setup request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2SessionSetupRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 session-setup request cannot be null.", nameof(request));
            }

            if ((request.SecurityMode & ~(Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 session-setup request security mode contains unsupported bits.", nameof(request));
            }

            if (request.SecurityBuffer.Length == 0)
            {
                throw new ProtocolValidationException("The SMB2 session-setup request must contain a security buffer.", nameof(request));
            }
        }
    }
}
