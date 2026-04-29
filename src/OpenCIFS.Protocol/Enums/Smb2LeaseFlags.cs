namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lease response flags.
    /// </summary>
    [Flags]
    public enum Smb2LeaseFlags : uint
    {
        /// <summary>
        /// No lease flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// A break for the lease is in progress.
        /// </summary>
        BreakInProgress = 0x00000002
    }
}
