namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 flush responses.
    /// </summary>
    public static class Smb2FlushResponseValidator
    {
        /// <summary>
        /// Validate a flush response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2FlushResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 flush response cannot be null.", nameof(response));
            }
        }
    }
}
