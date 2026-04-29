namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 tree-disconnect responses.
    /// </summary>
    public static class Smb2TreeDisconnectResponseValidator
    {
        /// <summary>
        /// Validate a tree-disconnect response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2TreeDisconnectResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 tree-disconnect response cannot be null.", nameof(response));
            }
        }
    }
}
