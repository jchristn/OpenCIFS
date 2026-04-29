namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 tree-disconnect requests.
    /// </summary>
    public static class Smb2TreeDisconnectRequestValidator
    {
        /// <summary>
        /// Validate a tree-disconnect request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2TreeDisconnectRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 tree-disconnect request cannot be null.", nameof(request));
            }
        }
    }
}
