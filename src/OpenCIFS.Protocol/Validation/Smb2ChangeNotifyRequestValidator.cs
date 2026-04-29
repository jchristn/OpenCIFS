namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 CHANGE_NOTIFY requests.
    /// </summary>
    public static class Smb2ChangeNotifyRequestValidator
    {
        private const FileNotifyChangeFilter SupportedCompletionFilters =
            FileNotifyChangeFilter.FileName |
            FileNotifyChangeFilter.DirName |
            FileNotifyChangeFilter.Attributes |
            FileNotifyChangeFilter.Size |
            FileNotifyChangeFilter.LastWrite |
            FileNotifyChangeFilter.LastAccess |
            FileNotifyChangeFilter.Creation;

        /// <summary>
        /// Validate a CHANGE_NOTIFY request.
        /// </summary>
        /// <param name="request">Request to validate.</param>
        public static void Validate(Smb2ChangeNotifyRequest request)
        {
            if (request == null)
            {
                throw new ProtocolValidationException("The SMB2 CHANGE_NOTIFY request cannot be null.", nameof(request));
            }

            if ((request.Flags & ~Smb2ChangeNotifyFlags.WatchTree) != 0)
            {
                throw new ProtocolValidationException("The SMB2 CHANGE_NOTIFY request contains flags that are not supported in the current slice.", nameof(request));
            }

            if (request.PersistentFileId == 0 && request.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 CHANGE_NOTIFY request must identify a directory handle.", nameof(request));
            }

            if ((request.CompletionFilter & ~SupportedCompletionFilters) != 0)
            {
                throw new ProtocolValidationException("The SMB2 CHANGE_NOTIFY request contains completion-filter bits that are not supported in the current slice.", nameof(request));
            }
        }
    }
}
