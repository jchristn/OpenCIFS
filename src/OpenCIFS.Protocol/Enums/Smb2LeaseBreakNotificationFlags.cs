namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 lease-break notification flags.
    /// </summary>
    [Flags]
    public enum Smb2LeaseBreakNotificationFlags : uint
    {
        /// <summary>
        /// No lease-break notification flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// A lease-break acknowledgment is required.
        /// </summary>
        AcknowledgmentRequired = 0x00000001
    }
}
