namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 flush requests.
    /// </summary>
    public static class Smb2FlushRequestValidator
    {
        /// <summary>
        /// Validate a flush request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2FlushRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 flush request cannot be null.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 flush request must carry a non-zero file identifier.", nameof(request));
            }
        }
    }
}
