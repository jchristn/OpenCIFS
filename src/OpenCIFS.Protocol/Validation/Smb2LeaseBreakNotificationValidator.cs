namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Validates SMB2 lease-break notifications.
    /// </summary>
    public static class Smb2LeaseBreakNotificationValidator
    {
        /// <summary>
        /// Validate a lease-break notification.
        /// </summary>
        /// <param name="notification">Notification to validate.</param>
        public static void Validate(Smb2LeaseBreakNotification notification)
        {
            if (notification == null)
            {
                throw new ProtocolValidationException("The SMB2 lease-break notification cannot be null.", nameof(notification));
            }

            if (notification.LeaseKey.Length != 16)
            {
                throw new ProtocolValidationException("The SMB2 lease-break notification must contain a 16-byte lease key.", nameof(notification));
            }

            if ((notification.Flags & ~Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired) != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break notification contains unsupported flags.", nameof(notification));
            }

            if ((notification.CurrentLeaseState & ~(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching)) != 0 ||
                (notification.NewLeaseState & ~(Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching)) != 0)
            {
                throw new ProtocolValidationException("The SMB2 lease-break notification contains unsupported lease-state bits.", nameof(notification));
            }
        }
    }
}
