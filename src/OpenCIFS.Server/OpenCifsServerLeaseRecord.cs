namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Shared SMB 2.1 lease state tracked across connection-scoped hosts.
    /// </summary>
    internal sealed class OpenCifsServerLeaseRecord
    {
        public Guid ClientGuid { get; set; }

        public byte[] LeaseKey
        {
            get
            {
                return _LeaseKey;
            }
            set
            {
                _LeaseKey = value ?? throw new ArgumentNullException(nameof(LeaseKey), "LeaseKey cannot be null.");
            }
        }

        public string FullPath { get; set; } = string.Empty;

        public Smb2LeaseState LeaseState { get; set; } = Smb2LeaseState.None;

        public Smb2LeaseState PendingBreakLeaseState { get; set; } = Smb2LeaseState.None;

        public bool IsBreaking { get; set; }

        public int OpenCount { get; set; }

        private byte[] _LeaseKey = new byte[16];
    }
}
