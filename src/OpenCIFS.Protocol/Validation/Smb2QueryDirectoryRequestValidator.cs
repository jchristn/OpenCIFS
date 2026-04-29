namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 query-directory requests.
    /// </summary>
    public static class Smb2QueryDirectoryRequestValidator
    {
        private const Smb2QueryDirectoryFlags SupportedFlags =
            Smb2QueryDirectoryFlags.RestartScans |
            Smb2QueryDirectoryFlags.ReturnSingleEntry |
            Smb2QueryDirectoryFlags.Reopen;

        /// <summary>
        /// Validate a query-directory request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2QueryDirectoryRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 query-directory request cannot be null.", nameof(request));
            }

            if (!Enum.IsDefined(typeof(FileInformationClass), request.FileInfoClass))
            {
                throw new ProtocolValidationException("The SMB2 query-directory request file information class is not recognized.", nameof(request));
            }

            if ((request.Flags & ~SupportedFlags) != 0)
            {
                throw new ProtocolValidationException("The SMB2 query-directory request contains flags that are not supported for the current directory-enumeration slice.", nameof(request));
            }

            if ((request.Flags & Smb2QueryDirectoryFlags.IndexSpecified) != 0)
            {
                throw new ProtocolValidationException("Index-based query-directory resumes are not supported for the current directory-enumeration slice.", nameof(request));
            }

            if (request.FileIndex != 0)
            {
                throw new ProtocolValidationException("The SMB2 query-directory request FileIndex field must remain zero for the current directory-enumeration slice.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 query-directory request must identify a directory handle.", nameof(request));
            }

            if (request.OutputBufferLength == 0)
            {
                throw new ProtocolValidationException("The SMB2 query-directory request must accept a non-zero output buffer.", nameof(request));
            }

            if (request.FileNamePattern.IndexOfAny(new char[] { '\\', '/' }) >= 0)
            {
                throw new ProtocolValidationException("The SMB2 query-directory request search pattern must not contain path separators.", nameof(request));
            }
        }
    }
}
