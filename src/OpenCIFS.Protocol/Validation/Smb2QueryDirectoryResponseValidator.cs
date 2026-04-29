namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 query-directory responses.
    /// </summary>
    public static class Smb2QueryDirectoryResponseValidator
    {
        /// <summary>
        /// Validate a query-directory response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2QueryDirectoryResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 query-directory response cannot be null.", nameof(response));
            }
        }
    }
}
