namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB1 headers.
    /// </summary>
    public static class Smb1HeaderValidator
    {
        /// <summary>
        /// Validate an SMB1 header.
        /// </summary>
        /// <param name="header">Header to validate.</param>
        public static void Validate(Smb1Header header)
        {
            if (header == null)
            {
                throw new ProtocolValidationException("The SMB1 header cannot be null.", nameof(header));
            }

            if (!Enum.IsDefined(typeof(Smb1Command), header.Command))
            {
                throw new ProtocolValidationException("The SMB1 command is not recognized.", nameof(header));
            }

            if ((byte)header.Flags != ((byte)header.Flags & 0xF8))
            {
                throw new ProtocolValidationException("The SMB1 header contains unsupported flag bits.", nameof(header));
            }

            if (header.Signature.Length != 8)
            {
                throw new ProtocolValidationException("The SMB1 signature length must be exactly 8 bytes.", nameof(header));
            }
        }
    }
}

