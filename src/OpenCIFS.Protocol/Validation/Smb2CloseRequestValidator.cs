namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 close requests.
    /// </summary>
    public static class Smb2CloseRequestValidator
    {
        /// <summary>
        /// Validate a close request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2CloseRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 close request cannot be null.", nameof(request));
            }

            if ((request.Flags & ~Smb2CloseFlags.PostQueryAttributes) != 0)
            {
                throw new ProtocolValidationException("The SMB2 close request contains unsupported flags.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 close request must carry a non-zero file identifier.", nameof(request));
            }
        }
    }
}
