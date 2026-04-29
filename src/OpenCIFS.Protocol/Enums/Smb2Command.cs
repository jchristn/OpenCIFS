namespace OpenCIFS.Protocol
{
    /// <summary>
    /// SMB2/3 command identifiers used by OpenCIFS foundations.
    /// </summary>
    public enum Smb2Command : ushort
    {
        /// <summary>
        /// Negotiate.
        /// </summary>
        Negotiate = 0x0000,

        /// <summary>
        /// Session setup.
        /// </summary>
        SessionSetup = 0x0001,

        /// <summary>
        /// Logoff.
        /// </summary>
        Logoff = 0x0002,

        /// <summary>
        /// Tree connect.
        /// </summary>
        TreeConnect = 0x0003,

        /// <summary>
        /// Tree disconnect.
        /// </summary>
        TreeDisconnect = 0x0004,

        /// <summary>
        /// Create.
        /// </summary>
        Create = 0x0005,

        /// <summary>
        /// Close.
        /// </summary>
        Close = 0x0006,

        /// <summary>
        /// Flush.
        /// </summary>
        Flush = 0x0007,

        /// <summary>
        /// Read.
        /// </summary>
        Read = 0x0008,

        /// <summary>
        /// Write.
        /// </summary>
        Write = 0x0009,

        /// <summary>
        /// Lock.
        /// </summary>
        Lock = 0x000A,

        /// <summary>
        /// IOCTL.
        /// </summary>
        Ioctl = 0x000B,

        /// <summary>
        /// Cancel.
        /// </summary>
        Cancel = 0x000C,

        /// <summary>
        /// Echo.
        /// </summary>
        Echo = 0x000D,

        /// <summary>
        /// Query directory.
        /// </summary>
        QueryDirectory = 0x000E,

        /// <summary>
        /// Change notify.
        /// </summary>
        ChangeNotify = 0x000F,

        /// <summary>
        /// Query info.
        /// </summary>
        QueryInfo = 0x0010,

        /// <summary>
        /// Set info.
        /// </summary>
        SetInfo = 0x0011,

        /// <summary>
        /// Oplock or lease break.
        /// </summary>
        OplockBreak = 0x0012
    }
}

