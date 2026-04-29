namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 oplock-break responses.
    /// </summary>
    public static class Smb2OplockBreakResponseValidator
    {
        /// <summary>
        /// Validate an oplock-break response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2OplockBreakResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break response cannot be null.", nameof(response));
            }

            if (!Enum.IsDefined(typeof(Smb2OplockLevel), response.OplockLevel) ||
                response.OplockLevel == Smb2OplockLevel.Batch ||
                response.OplockLevel == Smb2OplockLevel.Lease)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break response oplock level is not valid for the current SMB 2.0.2 slice.", nameof(response));
            }

            if (response.PersistentFileId == 0 && response.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break response file identifier must be non-zero.", nameof(response));
            }
        }
    }
}
