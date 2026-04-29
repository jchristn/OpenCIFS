namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 echo responses.
    /// </summary>
    public static class Smb2EchoResponseValidator
    {
        /// <summary>
        /// Validate an echo response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2EchoResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 echo response cannot be null.", nameof(response));
            }
        }
    }
}
