namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB2 CHANGE_NOTIFY request flags.
    /// </summary>
    [Flags]
    public enum Smb2ChangeNotifyFlags : ushort
    {
        /// <summary>
        /// Watch only immediate children of the directory open.
        /// </summary>
        None = 0x0000,

        /// <summary>
        /// Watch the full subtree beneath the directory open.
        /// </summary>
        WatchTree = 0x0001
    }
}
