namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 session-setup responses.
    /// </summary>
    public static class Smb2SessionSetupResponseValidator
    {
        /// <summary>
        /// Validate a session-setup response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2SessionSetupResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 session-setup response cannot be null.", nameof(response));
            }

            if ((response.SessionFlags & ~(Smb2SessionFlags.IsGuest | Smb2SessionFlags.IsNull | Smb2SessionFlags.EncryptData)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 session-setup response contains unsupported session-flag bits.", nameof(response));
            }
        }
    }
}
