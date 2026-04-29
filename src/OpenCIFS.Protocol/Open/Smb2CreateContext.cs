namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Generic SMB2 create-context entry.
    /// </summary>
    public sealed class Smb2CreateContext
    {
        /// <summary>
        /// Context name bytes.
        /// </summary>
        public byte[] Name
        {
            get
            {
                return _Name;
            }
            set
            {
                _Name = value ?? throw new ArgumentNullException(nameof(Name), "Name cannot be null.");
            }
        }

        /// <summary>
        /// Context payload bytes.
        /// </summary>
        public byte[] Data
        {
            get
            {
                return _Data;
            }
            set
            {
                _Data = value ?? throw new ArgumentNullException(nameof(Data), "Data cannot be null.");
            }
        }

        private byte[] _Name = Array.Empty<byte>();
        private byte[] _Data = Array.Empty<byte>();
    }
}
