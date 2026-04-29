namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 byte-range lock flags.
    /// </summary>
    public enum Smb2LockFlags : uint
    {
        /// <summary>
        /// No lock behavior flags.
        /// </summary>
        None = 0x00000000,

        /// <summary>
        /// Request a shared byte-range lock.
        /// </summary>
        SharedLock = 0x00000001,

        /// <summary>
        /// Request an exclusive byte-range lock.
        /// </summary>
        ExclusiveLock = 0x00000002,

        /// <summary>
        /// Release a previously acquired byte-range lock.
        /// </summary>
        Unlock = 0x00000004,

        /// <summary>
        /// Fail immediately on lock conflicts instead of waiting.
        /// </summary>
        FailImmediately = 0x00000010
    }
}
