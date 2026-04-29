namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 CHANGE_NOTIFY responses.
    /// </summary>
    public static class Smb2ChangeNotifyResponseValidator
    {
        /// <summary>
        /// Validate a CHANGE_NOTIFY response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2ChangeNotifyResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 CHANGE_NOTIFY response cannot be null.", nameof(response));
            }
        }
    }
}
