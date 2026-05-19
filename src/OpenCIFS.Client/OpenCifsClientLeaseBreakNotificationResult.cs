namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Applied state for an unsolicited SMB2 lease-break notification.
    /// </summary>
    public sealed class OpenCifsClientLeaseBreakNotificationResult
    {
        /// <summary>
        /// Initialize an applied lease-break result.
        /// </summary>
        /// <param name="openState">Tracked open state after the notification is applied.</param>
        /// <param name="previousLeaseState">Lease state before the notification.</param>
        /// <param name="newLeaseState">Lease state after the notification.</param>
        /// <param name="requiresAcknowledgment">Whether the client must acknowledge the break.</param>
        public OpenCifsClientLeaseBreakNotificationResult(
            OpenState openState,
            Smb2LeaseState previousLeaseState,
            Smb2LeaseState newLeaseState,
            bool requiresAcknowledgment)
        {
            OpenState = openState ?? throw new ArgumentNullException(nameof(openState));
            PreviousLeaseState = previousLeaseState;
            NewLeaseState = newLeaseState;
            RequiresAcknowledgment = requiresAcknowledgment;
        }

        /// <summary>
        /// Tracked open state after the notification is applied.
        /// </summary>
        public OpenState OpenState { get; }

        /// <summary>
        /// Lease state before the notification.
        /// </summary>
        public Smb2LeaseState PreviousLeaseState { get; }

        /// <summary>
        /// Lease state after the notification.
        /// </summary>
        public Smb2LeaseState NewLeaseState { get; }

        /// <summary>
        /// Whether the client must acknowledge the break.
        /// </summary>
        public bool RequiresAcknowledgment { get; }

        /// <summary>
        /// Deconstruct the applied lease-break notification result.
        /// </summary>
        /// <param name="openState">Tracked open state after the notification is applied.</param>
        /// <param name="previousLeaseState">Lease state before the notification.</param>
        /// <param name="newLeaseState">Lease state after the notification.</param>
        /// <param name="requiresAcknowledgment">Whether the client must acknowledge the break.</param>
        public void Deconstruct(
            out OpenState openState,
            out Smb2LeaseState previousLeaseState,
            out Smb2LeaseState newLeaseState,
            out bool requiresAcknowledgment)
        {
            openState = OpenState;
            previousLeaseState = PreviousLeaseState;
            newLeaseState = NewLeaseState;
            requiresAcknowledgment = RequiresAcknowledgment;
        }
    }
}
