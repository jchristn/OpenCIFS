namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 set-info requests.
    /// </summary>
    public static class Smb2SetInfoRequestValidator
    {
        /// <summary>
        /// Validate a set-info request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2SetInfoRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 set-info request cannot be null.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(Smb2InfoType), request.InfoType))
            {
                throw new ProtocolValidationException("The SMB2 set-info request info type is not recognized.", nameof(request));
            }

            if (request.InfoType != Smb2InfoType.File)
            {
                throw new ProtocolValidationException("The SMB2 set-info request info type is not supported for the current metadata slice.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(FileInformationClass), request.FileInfoClass))
            {
                throw new ProtocolValidationException("The SMB2 set-info request file information class is not recognized.", nameof(request));
            }

            if (request.Buffer.Length == 0)
            {
                throw new ProtocolValidationException("The SMB2 set-info request must include a non-empty buffer.", nameof(request));
            }

            if (request.AdditionalInformation != 0)
            {
                throw new ProtocolValidationException("The SMB2 set-info request additional-information field is not supported for the current metadata slice.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 set-info request must identify a file handle.", nameof(request));
            }
        }
    }
}
