namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 lock responses.
    /// </summary>
    public static class Smb2LockResponseValidator
    {
        /// <summary>
        /// Validate a lock response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2LockResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 lock response cannot be null.", nameof(response));
            }
        }
    }
}
