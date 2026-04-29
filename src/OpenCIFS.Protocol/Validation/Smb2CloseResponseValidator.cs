namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 close responses.
    /// </summary>
    public static class Smb2CloseResponseValidator
    {
        /// <summary>
        /// Validate a close response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2CloseResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 close response cannot be null.", nameof(response));
            }

            if ((response.Flags & ~Smb2CloseFlags.PostQueryAttributes) != 0)
            {
                throw new ProtocolValidationException("The SMB2 close response contains unsupported flags.", nameof(response));
            }
        }
    }
}
