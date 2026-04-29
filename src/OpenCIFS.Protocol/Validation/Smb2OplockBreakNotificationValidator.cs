namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// Validates SMB2 oplock-break notifications.
    /// </summary>
    public static class Smb2OplockBreakNotificationValidator
    {
        /// <summary>
        /// Validate an oplock-break notification.
        /// </summary>
        /// <param name="notification">Notification to validate.</param>
        public static void Validate(Smb2OplockBreakNotification notification)
        {
            if (notification == null)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break notification cannot be null.", nameof(notification));
            }

            if (!Enum.IsDefined(typeof(Smb2OplockLevel), notification.OplockLevel) ||
                notification.OplockLevel == Smb2OplockLevel.Batch ||
                notification.OplockLevel == Smb2OplockLevel.Lease)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break notification oplock level is not valid for the current SMB 2.0.2 slice.", nameof(notification));
            }

            if (notification.PersistentFileId == 0 && notification.VolatileFileId == 0)
            {
                throw new ProtocolValidationException("The SMB2 oplock-break notification file identifier must be non-zero.", nameof(notification));
            }
        }
    }
}
