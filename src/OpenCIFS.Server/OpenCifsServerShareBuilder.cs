namespace OpenCIFS.Server
{
    using System;

    /// <summary>
    /// Builder for a single share registration on the primary OpenCIFS server surface.
    /// </summary>
    public sealed class OpenCifsServerShareBuilder
    {
        internal OpenCifsServerShareBuilder(string shareName)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            ShareName = shareName;
        }

        /// <summary>
        /// Share name.
        /// </summary>
        public string ShareName { get; }

        /// <summary>
        /// Use the built-in local filesystem-backed share provider.
        /// </summary>
        /// <param name="rootPath">Backing filesystem root path.</param>
        /// <param name="createRootIfMissing">Whether the root should be created automatically.</param>
        /// <returns>The current share builder.</returns>
        public OpenCifsServerShareBuilder UseLocalFileSystem(string rootPath, bool createRootIfMissing = true)
        {
            if (string.IsNullOrWhiteSpace(rootPath))
            {
                throw new ArgumentNullException(nameof(rootPath), "RootPath cannot be null or whitespace.");
            }

            _ShareBackend = new OpenCifsServerFileSystemShare
            {
                ShareName = ShareName,
                RootPath = rootPath,
                CreateRootIfMissing = createRootIfMissing
            };

            return this;
        }

        internal OpenCifsServerShareBackend Build()
        {
            if (_ShareBackend == null)
            {
                throw new OpenCifsServerConfigurationException("A share registration must select a backing provider before it can be built.");
            }

            return _ShareBackend;
        }

        private OpenCifsServerShareBackend? _ShareBackend;
    }
}

