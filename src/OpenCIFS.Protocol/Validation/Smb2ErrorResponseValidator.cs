namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 error responses.
    /// </summary>
    public static class Smb2ErrorResponseValidator
    {
        /// <summary>
        /// Validate an SMB2 error response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2ErrorResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 error response cannot be null.", nameof(response));
            }
        }
    }
}
