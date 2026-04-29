namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 logoff responses.
    /// </summary>
    public static class Smb2LogoffResponseValidator
    {
        /// <summary>
        /// Validate a logoff response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2LogoffResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 logoff response cannot be null.", nameof(response));
            }
        }
    }
}
