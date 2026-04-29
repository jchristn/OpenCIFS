namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2/3 headers.
    /// </summary>
    public static class Smb2HeaderValidator
    {
        /// <summary>
        /// Validate an SMB2/3 header.
        /// </summary>
        /// <param name="header">Header to validate.</param>
        public static void Validate(Smb2Header header)
        {
            if (header == null)
            {
                throw new ProtocolValidationException("The SMB2/3 header cannot be null.", nameof(header));
            }

            if (!Enum.IsDefined(typeof(Smb2Command), header.Command))
            {
                throw new ProtocolValidationException("The SMB2/3 command is not recognized.", nameof(header));
            }

            if (header.NextCommand % 8 != 0)
            {
                throw new ProtocolValidationException("NextCommand must be aligned to an 8-byte boundary.", nameof(header));
            }

            if (header.Signature.Length != 16)
            {
                throw new ProtocolValidationException("The SMB2/3 signature length must be exactly 16 bytes.", nameof(header));
            }

            bool isAsync = (header.Flags & Smb2HeaderFlags.AsyncCommand) != 0;

            if (isAsync)
            {
                if (header.AsyncId == 0)
                {
                    throw new ProtocolValidationException("Asynchronous SMB2/3 headers must carry a non-zero AsyncId.", nameof(header));
                }

                if (header.ProcessId != 0 || header.TreeId != 0)
                {
                    throw new ProtocolValidationException("Asynchronous SMB2/3 headers must not carry synchronous ProcessId or TreeId values.", nameof(header));
                }
            }
            else if (header.AsyncId != 0)
            {
                throw new ProtocolValidationException("Synchronous SMB2/3 headers must not carry an AsyncId.", nameof(header));
            }
        }
    }
}
