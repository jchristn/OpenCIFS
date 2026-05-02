namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB1 DOS error class field carried in the legacy <c>SMB_HEADER.Status</c> shape used by
    /// pre-NT-aware peers per MS-CIFS section 2.2.2.4.
    /// </summary>
    public enum Smb1DosErrorClass : byte
    {
        /// <summary>
        /// No error.
        /// </summary>
        Success = 0x00,

        /// <summary>
        /// DOS / system error class.
        /// </summary>
        ErrDos = 0x01,

        /// <summary>
        /// Server error class.
        /// </summary>
        ErrSrv = 0x02,

        /// <summary>
        /// Hardware error class.
        /// </summary>
        ErrHrd = 0x03,

        /// <summary>
        /// Command not recognized.
        /// </summary>
        ErrCmd = 0xFF
    }
}
