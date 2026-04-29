namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 read responses.
    /// </summary>
    public static class Smb2ReadResponseValidator
    {
        /// <summary>
        /// Validate a read response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2ReadResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 read response cannot be null.", nameof(response));
            }

            if (response.DataRemaining != 0)
            {
                throw new ProtocolValidationException("The SMB2 read response data-remaining field must remain zero for the current SMB 2.0.2 slice.", nameof(response));
            }

            if (response.Flags != 0)
            {
                throw new ProtocolValidationException("The SMB2 read response contains unsupported flags for the current SMB 2.0.2 slice.", nameof(response));
            }

            if (response.DataBuffer.Length == 0)
            {
                throw new ProtocolValidationException("The SMB2 read response must contain at least one byte of data on success.", nameof(response));
            }
        }
    }
}
