namespace OpenCIFS.Protocol
{
    /// <summary>
    /// NTSTATUS values used by the OpenCIFS protocol foundation.
    /// </summary>
    public enum NtStatus : uint
    {
        /// <summary>
        /// Successful operation.
        /// </summary>
        Success = 0x00000000,

        /// <summary>
        /// No more matching files remain in the current enumeration.
        /// </summary>
        NoMoreFiles = 0x80000006,

        /// <summary>
        /// The request has entered asynchronous pending state.
        /// </summary>
        Pending = 0x00000103,

        /// <summary>
        /// More changes occurred than fit within the notify buffer.
        /// </summary>
        NotifyEnumDir = 0x0000010C,

        /// <summary>
        /// The output buffer was too small to hold the full response payload.
        /// </summary>
        BufferOverflow = 0x80000005,

        /// <summary>
        /// More processing is required.
        /// </summary>
        MoreProcessingRequired = 0xC0000016,

        /// <summary>
        /// Invalid information class.
        /// </summary>
        InvalidInfoClass = 0xC0000003,

        /// <summary>
        /// Information buffer length does not match the required shape.
        /// </summary>
        InfoLengthMismatch = 0xC0000004,

        /// <summary>
        /// A file or directory was not found.
        /// </summary>
        NoSuchFile = 0xC000000F,

        /// <summary>
        /// Access denied.
        /// </summary>
        AccessDenied = 0xC0000022,

        /// <summary>
        /// Buffer too small.
        /// </summary>
        BufferTooSmall = 0xC0000023,

        /// <summary>
        /// Invalid handle.
        /// </summary>
        InvalidHandle = 0xC0000008,

        /// <summary>
        /// Invalid parameter.
        /// </summary>
        InvalidParameter = 0xC000000D,

        /// <summary>
        /// Sharing violation.
        /// </summary>
        SharingViolation = 0xC0000043,

        /// <summary>
        /// A read or write conflicts with an existing byte-range lock.
        /// </summary>
        FileLockConflict = 0xC0000054,

        /// <summary>
        /// A requested byte-range lock could not be granted.
        /// </summary>
        LockNotGranted = 0xC0000055,

        /// <summary>
        /// Delete pending.
        /// </summary>
        DeletePending = 0xC0000056,

        /// <summary>
        /// The requested unlock range is not currently locked by the open.
        /// </summary>
        RangeNotLocked = 0xC000007E,

        /// <summary>
        /// Object name not found.
        /// </summary>
        ObjectNameNotFound = 0xC0000034,

        /// <summary>
        /// Object name collision.
        /// </summary>
        ObjectNameCollision = 0xC0000035,

        /// <summary>
        /// Object path not found.
        /// </summary>
        ObjectPathNotFound = 0xC000003A,

        /// <summary>
        /// End of file.
        /// </summary>
        EndOfFile = 0xC0000011,

        /// <summary>
        /// File handle has been closed.
        /// </summary>
        FileClosed = 0xC0000128,

        /// <summary>
        /// The target path is a directory but the caller requested a non-directory open.
        /// </summary>
        FileIsADirectory = 0xC00000BA,

        /// <summary>
        /// The oplock acknowledgment does not match the current server-side state.
        /// </summary>
        InvalidOplockProtocol = 0xC00000E3,

        /// <summary>
        /// The target path is not a directory but the caller requested a directory open.
        /// </summary>
        NotADirectory = 0xC0000103,

        /// <summary>
        /// The target directory is not empty.
        /// </summary>
        DirectoryNotEmpty = 0xC0000101,

        /// <summary>
        /// Not supported.
        /// </summary>
        NotSupported = 0xC00000BB,

        /// <summary>
        /// A filesystem driver is required for the requested operation.
        /// </summary>
        FsDriverRequired = 0xC000019C,

        /// <summary>
        /// The contacted server does not cover the requested DFS namespace path.
        /// </summary>
        PathNotCovered = 0xC0000257,

        /// <summary>
        /// Cancelled operation.
        /// </summary>
        Cancelled = 0xC0000120,

        /// <summary>
        /// The target object is not in a valid state for the requested operation.
        /// </summary>
        InvalidDeviceState = 0xC0000184,

        /// <summary>
        /// The target cannot be deleted in its current state.
        /// </summary>
        CannotDelete = 0xC0000121,

        /// <summary>
        /// Generic unsuccessful operation. <c>STATUS_UNSUCCESSFUL</c>.
        /// </summary>
        Unsuccessful = 0xC0000001,

        /// <summary>
        /// The requested device or operation is not supported. <c>STATUS_INVALID_DEVICE_REQUEST</c>.
        /// </summary>
        InvalidDeviceRequest = 0xC0000010,

        /// <summary>
        /// Logon failure (bad credentials). <c>STATUS_LOGON_FAILURE</c>.
        /// </summary>
        LogonFailure = 0xC000006D,

        /// <summary>
        /// Disk full. <c>STATUS_DISK_FULL</c>.
        /// </summary>
        DiskFull = 0xC000007F,

        /// <summary>
        /// Insufficient server resources. <c>STATUS_INSUFFICIENT_RESOURCES</c>.
        /// </summary>
        InsufficientResources = 0xC000009A,

        /// <summary>
        /// Network name (tree) has been deleted. <c>STATUS_NETWORK_NAME_DELETED</c>.
        /// </summary>
        NetworkNameDeleted = 0xC00000C9,

        /// <summary>
        /// Bad network name (share not found). <c>STATUS_BAD_NETWORK_NAME</c>.
        /// </summary>
        BadNetworkName = 0xC00000CC,

        /// <summary>
        /// Too many open files. <c>STATUS_TOO_MANY_OPENED_FILES</c>.
        /// </summary>
        TooManyOpenedFiles = 0xC000011F,

        /// <summary>
        /// User session has been deleted. <c>STATUS_USER_SESSION_DELETED</c>.
        /// </summary>
        UserSessionDeleted = 0xC0000203
    }
}
