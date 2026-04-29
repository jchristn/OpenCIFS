namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 query-info responses.
    /// </summary>
    public static class Smb2QueryInfoResponseValidator
    {
        /// <summary>
        /// Validate a query-info response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2QueryInfoResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 query-info response cannot be null.", nameof(response));
            }
        }
    }
}
