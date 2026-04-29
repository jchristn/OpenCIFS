namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 tree-connect requests.
    /// </summary>
    public static class Smb2TreeConnectRequestValidator
    {
        /// <summary>
        /// Validate a tree-connect request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2TreeConnectRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 tree-connect request cannot be null.", nameof(request));
            }

            if (string.IsNullOrWhiteSpace(request.Path))
            {
                throw new ProtocolValidationException("The SMB2 tree-connect request path cannot be null or whitespace.", nameof(request));
            }
        }
    }
}
