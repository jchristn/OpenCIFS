namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Applied state for an unsolicited SMB2 oplock-break notification.
    /// </summary>
    public sealed class OpenCifsClientOplockBreakNotificationResult
    {
        /// <summary>
        /// Initialize an applied oplock-break result.
        /// </summary>
        /// <param name="openState">Tracked open state after the notification is applied.</param>
        /// <param name="previousOplockLevel">Oplock level before the notification.</param>
        /// <param name="newOplockLevel">Oplock level after the notification.</param>
        /// <param name="requiresAcknowledgment">Whether the client must acknowledge the break.</param>
        public OpenCifsClientOplockBreakNotificationResult(
            OpenState openState,
            Smb2OplockLevel previousOplockLevel,
            Smb2OplockLevel newOplockLevel,
            bool requiresAcknowledgment)
        {
            OpenState = openState ?? throw new ArgumentNullException(nameof(openState));
            PreviousOplockLevel = previousOplockLevel;
            NewOplockLevel = newOplockLevel;
            RequiresAcknowledgment = requiresAcknowledgment;
        }

        /// <summary>
        /// Tracked open state after the notification is applied.
        /// </summary>
        public OpenState OpenState { get; }

        /// <summary>
        /// Oplock level before the notification.
        /// </summary>
        public Smb2OplockLevel PreviousOplockLevel { get; }

        /// <summary>
        /// Oplock level after the notification.
        /// </summary>
        public Smb2OplockLevel NewOplockLevel { get; }

        /// <summary>
        /// Whether the client must acknowledge the break.
        /// </summary>
        public bool RequiresAcknowledgment { get; }

        /// <summary>
        /// Deconstruct the applied oplock-break notification result.
        /// </summary>
        /// <param name="openState">Tracked open state after the notification is applied.</param>
        /// <param name="previousOplockLevel">Oplock level before the notification.</param>
        /// <param name="newOplockLevel">Oplock level after the notification.</param>
        /// <param name="requiresAcknowledgment">Whether the client must acknowledge the break.</param>
        public void Deconstruct(
            out OpenState openState,
            out Smb2OplockLevel previousOplockLevel,
            out Smb2OplockLevel newOplockLevel,
            out bool requiresAcknowledgment)
        {
            openState = OpenState;
            previousOplockLevel = PreviousOplockLevel;
            newOplockLevel = NewOplockLevel;
            requiresAcknowledgment = RequiresAcknowledgment;
        }
    }
}
