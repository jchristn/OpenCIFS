namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 negotiate requests.
    /// </summary>
    public static class Smb2NegotiateRequestValidator
    {
        /// <summary>
        /// Validate a negotiate request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2NegotiateRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 negotiate request cannot be null.", nameof(request));
            }

            if ((request.SecurityMode & ~(Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 negotiate request security mode contains unsupported bits.", nameof(request));
            }

            if (request.Dialects.Length == 0)
            {
                throw new ProtocolValidationException("The SMB2 negotiate request must carry at least one dialect.", nameof(request));
            }

            bool requiresClientGuid = false;

            for (int index = 0; index < request.Dialects.Length; index++)
            {
                if (request.Dialects[index] == SmbDialect.Cifs10)
                {
                    throw new ProtocolValidationException("SMB2 negotiate requests must not advertise SMB1/CIFS dialects.", nameof(request));
                }

                if (request.Dialects[index] >= SmbDialect.Smb21)
                {
                    requiresClientGuid = true;
                }

                for (int duplicateIndex = index + 1; duplicateIndex < request.Dialects.Length; duplicateIndex++)
                {
                    if (request.Dialects[index] == request.Dialects[duplicateIndex])
                    {
                        throw new ProtocolValidationException("SMB2 negotiate requests must not contain duplicate dialects.", nameof(request));
                    }
                }
            }

            if (requiresClientGuid && request.ClientGuid == Guid.Empty)
            {
                throw new ProtocolValidationException("SMB 2.1 and newer negotiate requests must carry a non-empty client GUID.", nameof(request));
            }
        }
    }
}
