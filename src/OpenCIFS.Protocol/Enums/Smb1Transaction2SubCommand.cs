namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB1 <c>SMB_COM_TRANSACTION2</c> sub-command codes carried in the request setup words per
    /// MS-CIFS section 2.2.6.
    /// </summary>
    public enum Smb1Transaction2SubCommand : ushort
    {
        /// <summary>
        /// Open or create a file with extended attributes.
        /// </summary>
        Open2 = 0x0000,

        /// <summary>
        /// Begin enumerating a directory.
        /// </summary>
        FindFirst2 = 0x0001,

        /// <summary>
        /// Continue an in-progress directory enumeration.
        /// </summary>
        FindNext2 = 0x0002,

        /// <summary>
        /// Query filesystem information.
        /// </summary>
        QueryFsInformation = 0x0003,

        /// <summary>
        /// Set filesystem information.
        /// </summary>
        SetFsInformation = 0x0004,

        /// <summary>
        /// Query attributes by path.
        /// </summary>
        QueryPathInformation = 0x0005,

        /// <summary>
        /// Set attributes by path.
        /// </summary>
        SetPathInformation = 0x0006,

        /// <summary>
        /// Query attributes by FID.
        /// </summary>
        QueryFileInformation = 0x0007,

        /// <summary>
        /// Set attributes by FID.
        /// </summary>
        SetFileInformation = 0x0008,

        /// <summary>
        /// Notify directory change. Largely subsumed by NT_TRANSACT_NOTIFY_CHANGE on NT-aware clients.
        /// </summary>
        FsctlOrNotifyChange = 0x0009,

        /// <summary>
        /// Create directory with extended attributes.
        /// </summary>
        CreateDirectory = 0x000D,

        /// <summary>
        /// Session setup follow-up (rare; superseded by SESSION_SETUP_ANDX on NT-aware clients).
        /// </summary>
        SessionSetup = 0x000E,

        /// <summary>
        /// Get DFS referral information.
        /// </summary>
        GetDfsReferral = 0x0010,

        /// <summary>
        /// Report DFS inconsistency.
        /// </summary>
        ReportDfsInconsistency = 0x0011
    }
}
