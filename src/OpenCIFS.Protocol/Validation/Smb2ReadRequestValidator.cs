namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 read requests.
    /// </summary>
    public static class Smb2ReadRequestValidator
    {
        /// <summary>
        /// Validate a read request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2ReadRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 read request cannot be null.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 read request must carry a non-zero file identifier.", nameof(request));
            }

            if (request.Channel != 0 || request.RemainingBytes != 0 || request.ReadChannelInfo.Length != 0)
            {
                throw new ProtocolValidationException("The SMB2 read request channel fields must remain zero for the current SMB 2.0.2 slice.", nameof(request));
            }
        }
    }
}
