namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 write responses.
    /// </summary>
    public static class Smb2WriteResponseValidator
    {
        /// <summary>
        /// Validate a write response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2WriteResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 write response cannot be null.", nameof(response));
            }
        }
    }
}
