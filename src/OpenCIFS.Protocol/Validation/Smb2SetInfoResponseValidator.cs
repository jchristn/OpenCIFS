namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 set-info responses.
    /// </summary>
    public static class Smb2SetInfoResponseValidator
    {
        /// <summary>
        /// Validate a set-info response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2SetInfoResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 set-info response cannot be null.", nameof(response));
            }
        }
    }
}
