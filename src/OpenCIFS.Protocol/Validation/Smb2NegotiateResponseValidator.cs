namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 negotiate responses.
    /// </summary>
    public static class Smb2NegotiateResponseValidator
    {
        /// <summary>
        /// Validate a negotiate response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2NegotiateResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 negotiate response cannot be null.", nameof(response));
            }

            if (response.Dialect == SmbDialect.Cifs10)
            {
                throw new ProtocolValidationException("SMB2 negotiate responses must not select the SMB1/CIFS dialect.", nameof(response));
            }

            if ((response.SecurityMode & ~(Smb2SecurityMode.SigningEnabled | Smb2SecurityMode.SigningRequired)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 negotiate response security mode contains unsupported bits.", nameof(response));
            }

            if ((response.SecurityMode & Smb2SecurityMode.SigningRequired) != 0 &&
                (response.SecurityMode & Smb2SecurityMode.SigningEnabled) == 0)
            {
                throw new ProtocolValidationException("SigningRequired cannot be set without SigningEnabled.", nameof(response));
            }

            if (response.ServerGuid == Guid.Empty)
            {
                throw new ProtocolValidationException("The SMB2 negotiate response must carry a non-empty server GUID.", nameof(response));
            }

            if (response.MaxTransactSize == 0 || response.MaxReadSize == 0 || response.MaxWriteSize == 0)
            {
                throw new ProtocolValidationException("The SMB2 negotiate response maximum sizes must be greater than zero.", nameof(response));
            }
        }
    }
}
