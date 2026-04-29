namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Metadata describing an FSCC information class.
    /// </summary>
    public sealed class FsccInformationClassInfo
    {
        /// <summary>
        /// Display name.
        /// </summary>
        public string Name
        {
            get
            {
                return _Name;
            }
            set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(Name), "Name cannot be null or whitespace.");
                }

                _Name = value;
            }
        }

        /// <summary>
        /// Description.
        /// </summary>
        public string Description
        {
            get
            {
                return _Description;
            }
            set
            {
                if (String.IsNullOrWhiteSpace(value))
                {
                    throw new ArgumentNullException(nameof(Description), "Description cannot be null or whitespace.");
                }

                _Description = value;
            }
        }

        /// <summary>
        /// Whether a file handle is required.
        /// </summary>
        public bool RequiresFileHandle { get; set; } = true;

        private string _Name = String.Empty;
        private string _Description = String.Empty;
    }
}

