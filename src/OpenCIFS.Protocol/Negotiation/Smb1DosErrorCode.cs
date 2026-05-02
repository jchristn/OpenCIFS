namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Common SMB1 DOS error code values carried in the <c>SMB_HEADER.Status</c> code field per
    /// MS-CIFS section 2.2.2.4.
    /// </summary>
    public static class Smb1DosErrorCode
    {
        /// <summary>
        /// Invalid function. ERRDOS.
        /// </summary>
        public const ushort BadFunction = 0x0001;

        /// <summary>
        /// File not found. ERRDOS.
        /// </summary>
        public const ushort BadFile = 0x0002;

        /// <summary>
        /// Path not found. ERRDOS.
        /// </summary>
        public const ushort BadPath = 0x0003;

        /// <summary>
        /// Too many open files. ERRDOS.
        /// </summary>
        public const ushort NoFids = 0x0004;

        /// <summary>
        /// Access denied. ERRDOS.
        /// </summary>
        public const ushort NoAccess = 0x0005;

        /// <summary>
        /// Invalid file handle. ERRDOS.
        /// </summary>
        public const ushort BadFid = 0x0006;

        /// <summary>
        /// Insufficient memory. ERRDOS.
        /// </summary>
        public const ushort NoMemory = 0x0008;

        /// <summary>
        /// Cannot create another file. ERRDOS.
        /// </summary>
        public const ushort NoFiles = 0x0012;

        /// <summary>
        /// File exists. ERRDOS.
        /// </summary>
        public const ushort FileExists = 0x0050;

        /// <summary>
        /// Invalid parameter. ERRDOS.
        /// </summary>
        public const ushort InvalidParameter = 0x0057;

        /// <summary>
        /// Lock conflict. ERRDOS or ERRHRD.
        /// </summary>
        public const ushort Lock = 0x0021;

        /// <summary>
        /// Share-mode conflict. ERRDOS or ERRHRD.
        /// </summary>
        public const ushort BadShare = 0x0020;

        /// <summary>
        /// Disk full. ERRHRD.
        /// </summary>
        public const ushort DiskFull = 0x0027;

        /// <summary>
        /// Buffer overflow / more data available. ERRDOS.
        /// </summary>
        public const ushort MoreData = 0x00EA;

        /// <summary>
        /// Range not locked. ERRDOS.
        /// </summary>
        public const ushort NotLocked = 0x009E;

        /// <summary>
        /// Generic error. ERRSRV.
        /// </summary>
        public const ushort Error = 0x0001;

        /// <summary>
        /// Bad password. ERRSRV.
        /// </summary>
        public const ushort BadPassword = 0x0002;

        /// <summary>
        /// Invalid TID. ERRSRV.
        /// </summary>
        public const ushort InvalidTid = 0x0005;

        /// <summary>
        /// Invalid network name. ERRSRV.
        /// </summary>
        public const ushort InvalidNetworkName = 0x0006;

        /// <summary>
        /// Invalid device. ERRSRV.
        /// </summary>
        public const ushort InvalidDevice = 0x0007;

        /// <summary>
        /// Command unsupported. ERRSRV.
        /// </summary>
        public const ushort UnsupportedCommand = 0x0040;

        /// <summary>
        /// Invalid UID. ERRSRV.
        /// </summary>
        public const ushort BadUid = 0x005B;
    }
}
