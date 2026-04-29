namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2 oplock levels used by create requests and responses.
    /// </summary>
    public enum Smb2OplockLevel : byte
    {
        /// <summary>
        /// No oplock.
        /// </summary>
        None = 0x00,

        /// <summary>
        /// Level II oplock.
        /// </summary>
        LevelII = 0x01,

        /// <summary>
        /// Exclusive oplock.
        /// </summary>
        Exclusive = 0x08,

        /// <summary>
        /// Batch oplock.
        /// </summary>
        Batch = 0x09,

        /// <summary>
        /// Lease oplock. Not valid for SMB 2.0.2.
        /// </summary>
        Lease = 0xFF
    }
}
