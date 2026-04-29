namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 query-info requests.
    /// </summary>
    public static class Smb2QueryInfoRequestValidator
    {
        /// <summary>
        /// Validate a query-info request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2QueryInfoRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 query-info request cannot be null.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(Smb2InfoType), request.InfoType))
            {
                throw new ProtocolValidationException("The SMB2 query-info request info type is not recognized.", nameof(request));
            }

            if (request.InfoType != Smb2InfoType.File && request.InfoType != Smb2InfoType.FileSystem)
            {
                throw new ProtocolValidationException("The SMB2 query-info request info type is not supported for the current metadata slice.", nameof(request));
            }

            if (request.InfoType == Smb2InfoType.File &&
                !Enum.IsDefined(typeof(FileInformationClass), request.FileInfoClass))
            {
                throw new ProtocolValidationException("The SMB2 query-info request file information class is not recognized.", nameof(request));
            }

            if (request.InfoType == Smb2InfoType.FileSystem &&
                !Enum.IsDefined(typeof(FileSystemInformationClass), (FileSystemInformationClass)(byte)request.FileInfoClass))
            {
                throw new ProtocolValidationException("The SMB2 query-info request filesystem information class is not recognized.", nameof(request));
            }

            if (request.InputBuffer.Length != 0)
            {
                throw new ProtocolValidationException("The SMB2 query-info request input buffer is not supported for the current metadata slice.", nameof(request));
            }

            if (request.AdditionalInformation != 0)
            {
                throw new ProtocolValidationException("The SMB2 query-info request additional-information field is not supported for the current metadata slice.", nameof(request));
            }

            if (request.Flags != 0)
            {
                throw new ProtocolValidationException("The SMB2 query-info request flags field is not supported for the current metadata slice.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 query-info request must identify a file handle.", nameof(request));
            }
        }
    }
}
