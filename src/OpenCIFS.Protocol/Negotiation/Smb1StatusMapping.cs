namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Bidirectional mapping between modern <see cref="NtStatus" /> values and the legacy SMB1
    /// DOS error class plus error code pair carried in the pre-NT-aware <c>SMB_HEADER.Status</c>
    /// shape per MS-CIFS section 2.2.2.4.
    /// </summary>
    /// <remarks>
    /// Modern OpenCIFS clients and servers always set <see cref="Smb1HeaderFlags2.NtStatus" /> on
    /// the carrying header so the 4-byte status field already carries an NTSTATUS value directly.
    /// This mapping table exists for the bounded SMB1 dispatch slice that has to interoperate
    /// with pre-NT-aware peers, for surface diagnostics that translate an NTSTATUS into the
    /// equivalent class plus code pair, and for the symmetric direction when accepting traffic
    /// from a peer that did not set the NtStatus bit on its header.
    /// </remarks>
    public static class Smb1StatusMapping
    {
        /// <summary>
        /// Translate an <see cref="NtStatus" /> value into the legacy SMB1 DOS error class plus
        /// error code pair.
        /// </summary>
        /// <param name="status">NTSTATUS value to map.</param>
        /// <param name="errorClass">Output DOS error class.</param>
        /// <param name="errorCode">Output DOS error code.</param>
        public static void NtStatusToDosError(NtStatus status, out Smb1DosErrorClass errorClass, out ushort errorCode)
        {
            switch (status)
            {
                case NtStatus.Success:
                    errorClass = Smb1DosErrorClass.Success;
                    errorCode = 0x0000;
                    return;
                case NtStatus.NoSuchFile:
                case NtStatus.ObjectNameNotFound:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.BadFile;
                    return;
                case NtStatus.ObjectPathNotFound:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.BadPath;
                    return;
                case NtStatus.AccessDenied:
                case NtStatus.CannotDelete:
                case NtStatus.DeletePending:
                case NtStatus.DirectoryNotEmpty:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.NoAccess;
                    return;
                case NtStatus.InvalidHandle:
                case NtStatus.FileClosed:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.BadFid;
                    return;
                case NtStatus.InvalidParameter:
                case NtStatus.InvalidInfoClass:
                case NtStatus.InfoLengthMismatch:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.InvalidParameter;
                    return;
                case NtStatus.SharingViolation:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.BadShare;
                    return;
                case NtStatus.FileLockConflict:
                case NtStatus.LockNotGranted:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.Lock;
                    return;
                case NtStatus.RangeNotLocked:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.NotLocked;
                    return;
                case NtStatus.ObjectNameCollision:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.FileExists;
                    return;
                case NtStatus.NoMoreFiles:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.NoFiles;
                    return;
                case NtStatus.BufferOverflow:
                case NtStatus.BufferTooSmall:
                    errorClass = Smb1DosErrorClass.ErrDos;
                    errorCode = Smb1DosErrorCode.MoreData;
                    return;
                case NtStatus.NetworkNameDeleted:
                    errorClass = Smb1DosErrorClass.ErrSrv;
                    errorCode = Smb1DosErrorCode.InvalidTid;
                    return;
                case NtStatus.BadNetworkName:
                    errorClass = Smb1DosErrorClass.ErrSrv;
                    errorCode = Smb1DosErrorCode.InvalidNetworkName;
                    return;
                case NtStatus.LogonFailure:
                    errorClass = Smb1DosErrorClass.ErrSrv;
                    errorCode = Smb1DosErrorCode.BadPassword;
                    return;
                case NtStatus.NotSupported:
                case NtStatus.InvalidDeviceRequest:
                case NtStatus.InvalidDeviceState:
                    errorClass = Smb1DosErrorClass.ErrSrv;
                    errorCode = Smb1DosErrorCode.UnsupportedCommand;
                    return;
                case NtStatus.UserSessionDeleted:
                    errorClass = Smb1DosErrorClass.ErrSrv;
                    errorCode = Smb1DosErrorCode.BadUid;
                    return;
                case NtStatus.DiskFull:
                    errorClass = Smb1DosErrorClass.ErrHrd;
                    errorCode = Smb1DosErrorCode.DiskFull;
                    return;
                default:
                    errorClass = Smb1DosErrorClass.ErrSrv;
                    errorCode = Smb1DosErrorCode.Error;
                    return;
            }
        }

        /// <summary>
        /// Translate a legacy SMB1 DOS error class plus error code pair into the most appropriate
        /// modern <see cref="NtStatus" /> value.
        /// </summary>
        /// <param name="errorClass">DOS error class.</param>
        /// <param name="errorCode">DOS error code.</param>
        /// <returns>Corresponding <see cref="NtStatus" />.</returns>
        public static NtStatus DosErrorToNtStatus(Smb1DosErrorClass errorClass, ushort errorCode)
        {
            if (errorClass == Smb1DosErrorClass.Success && errorCode == 0)
            {
                return NtStatus.Success;
            }

            switch (errorClass)
            {
                case Smb1DosErrorClass.ErrDos:
                    switch (errorCode)
                    {
                        case Smb1DosErrorCode.BadFile: return NtStatus.ObjectNameNotFound;
                        case Smb1DosErrorCode.BadPath: return NtStatus.ObjectPathNotFound;
                        case Smb1DosErrorCode.NoFids: return NtStatus.TooManyOpenedFiles;
                        case Smb1DosErrorCode.NoAccess: return NtStatus.AccessDenied;
                        case Smb1DosErrorCode.BadFid: return NtStatus.InvalidHandle;
                        case Smb1DosErrorCode.NoMemory: return NtStatus.InsufficientResources;
                        case Smb1DosErrorCode.NoFiles: return NtStatus.NoMoreFiles;
                        case Smb1DosErrorCode.FileExists: return NtStatus.ObjectNameCollision;
                        case Smb1DosErrorCode.InvalidParameter: return NtStatus.InvalidParameter;
                        case Smb1DosErrorCode.Lock: return NtStatus.FileLockConflict;
                        case Smb1DosErrorCode.BadShare: return NtStatus.SharingViolation;
                        case Smb1DosErrorCode.MoreData: return NtStatus.BufferOverflow;
                        case Smb1DosErrorCode.NotLocked: return NtStatus.RangeNotLocked;
                        default: return NtStatus.Unsuccessful;
                    }
                case Smb1DosErrorClass.ErrSrv:
                    switch (errorCode)
                    {
                        case Smb1DosErrorCode.BadPassword: return NtStatus.LogonFailure;
                        case Smb1DosErrorCode.InvalidTid: return NtStatus.NetworkNameDeleted;
                        case Smb1DosErrorCode.InvalidNetworkName: return NtStatus.BadNetworkName;
                        case Smb1DosErrorCode.UnsupportedCommand: return NtStatus.NotSupported;
                        case Smb1DosErrorCode.BadUid: return NtStatus.UserSessionDeleted;
                        default: return NtStatus.Unsuccessful;
                    }
                case Smb1DosErrorClass.ErrHrd:
                    switch (errorCode)
                    {
                        case Smb1DosErrorCode.DiskFull: return NtStatus.DiskFull;
                        case Smb1DosErrorCode.BadShare: return NtStatus.SharingViolation;
                        case Smb1DosErrorCode.Lock: return NtStatus.FileLockConflict;
                        default: return NtStatus.Unsuccessful;
                    }
                case Smb1DosErrorClass.ErrCmd:
                    return NtStatus.NotSupported;
                default:
                    return NtStatus.Unsuccessful;
            }
        }

        /// <summary>
        /// Pack an <see cref="NtStatus" /> into the legacy SMB1 4-byte <c>Status</c> field shape
        /// (ErrorClass | Reserved | ErrorCode LE) used when the carrying header does not have the
        /// <see cref="Smb1HeaderFlags2.NtStatus" /> bit set.
        /// </summary>
        /// <param name="status">NTSTATUS value to map and pack.</param>
        /// <returns>Packed legacy 4-byte status field value.</returns>
        public static uint PackNtStatusToLegacyStatusField(NtStatus status)
        {
            NtStatusToDosError(status, out Smb1DosErrorClass errorClass, out ushort errorCode);
            return ((uint)errorClass) | (((uint)errorCode) << 16);
        }

        /// <summary>
        /// Unpack the legacy SMB1 4-byte <c>Status</c> field into an <see cref="NtStatus" />.
        /// </summary>
        /// <param name="legacyStatusField">Packed legacy status field value.</param>
        /// <returns>Mapped <see cref="NtStatus" />.</returns>
        public static NtStatus UnpackLegacyStatusFieldToNtStatus(uint legacyStatusField)
        {
            Smb1DosErrorClass errorClass = (Smb1DosErrorClass)(byte)(legacyStatusField & 0xFF);
            ushort errorCode = (ushort)((legacyStatusField >> 16) & 0xFFFF);
            return DosErrorToNtStatus(errorClass, errorCode);
        }
    }
}
