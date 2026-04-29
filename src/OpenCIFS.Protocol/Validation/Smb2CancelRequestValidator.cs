namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 cancel requests.
    /// </summary>
    public static class Smb2CancelRequestValidator
    {
        /// <summary>
        /// Validate a cancel request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2CancelRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 cancel request cannot be null.", nameof(request));
            }
        }
    }
}
