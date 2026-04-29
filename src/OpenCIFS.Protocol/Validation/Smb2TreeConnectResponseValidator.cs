namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 tree-connect responses.
    /// </summary>
    public static class Smb2TreeConnectResponseValidator
    {
        /// <summary>
        /// Validate a tree-connect response.
        /// </summary>
        /// <param name="response">Response to validate.</param>
        public static void Validate(Smb2TreeConnectResponse response)
        {
            if (response == null)
            {
                throw new ProtocolValidationException("The SMB2 tree-connect response cannot be null.", nameof(response));
            }

            if (!Enum.IsDefined(typeof(Smb2ShareType), response.ShareType))
            {
                throw new ProtocolValidationException("The SMB2 tree-connect response share type is not recognized.", nameof(response));
            }
        }
    }
}
