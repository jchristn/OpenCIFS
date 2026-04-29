namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 echo requests.
    /// </summary>
    public static class Smb2EchoRequestValidator
    {
        /// <summary>
        /// Validate an echo request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2EchoRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 echo request cannot be null.", nameof(request));
            }
        }
    }
}
