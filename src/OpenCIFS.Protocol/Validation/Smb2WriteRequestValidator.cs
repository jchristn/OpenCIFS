namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 write requests.
    /// </summary>
    public static class Smb2WriteRequestValidator
    {
        /// <summary>
        /// Validate a write request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2WriteRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 write request cannot be null.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 write request must carry a non-zero file identifier.", nameof(request));
            }

            if (request.Channel != 0 || request.RemainingBytes != 0 || request.WriteChannelInfo.Length != 0)
            {
                throw new ProtocolValidationException("The SMB2 write request channel fields must remain zero for the current SMB 2.0.2 slice.", nameof(request));
            }

            if (request.Flags != Smb2WriteFlags.None)
            {
                throw new ProtocolValidationException("The SMB2 write request flags are not supported for the current SMB 2.0.2 slice.", nameof(request));
            }
        }
    }
}
