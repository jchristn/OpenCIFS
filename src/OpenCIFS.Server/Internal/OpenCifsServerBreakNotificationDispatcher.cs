namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerBreakNotificationDispatcher
    {
        private readonly Action<ServerOpenRecord, byte[]> _EnqueueNotificationPayload;
        private readonly OpenCifsServerOpenStateTracker _OpenStateTracker;

        public OpenCifsServerBreakNotificationDispatcher(OpenCifsServerOpenStateTracker openStateTracker, Action<ServerOpenRecord, byte[]> enqueueNotificationPayload)
        {
            _OpenStateTracker = openStateTracker ?? throw new ArgumentNullException(nameof(openStateTracker), "OpenStateTracker cannot be null.");
            _EnqueueNotificationPayload = enqueueNotificationPayload ?? throw new ArgumentNullException(nameof(enqueueNotificationPayload), "EnqueueNotificationPayload cannot be null.");
        }

        public void QueueBreakNotificationsForConflictingOpens(string fullPath, ServerOpenRecord excludedOpenRecord)
        {
            List<ServerOpenRecord> matchingOpens = _OpenStateTracker.GetOpenRecordsForPath(fullPath);
            QueueOplockBreakNotifications(matchingOpens, excludedOpenRecord);
            QueueLeaseBreakNotifications(matchingOpens, excludedOpenRecord);
        }

        private void QueueOplockBreakNotifications(IReadOnlyList<ServerOpenRecord> matchingOpens, ServerOpenRecord excludedOpenRecord)
        {
            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];

                if (ReferenceEquals(openRecord, excludedOpenRecord) ||
                    openRecord.IsDirectory ||
                    (openRecord.GrantedOplockLevel != Smb2OplockLevel.Exclusive && openRecord.GrantedOplockLevel != Smb2OplockLevel.Batch) ||
                    openRecord.IsOplockBreakInProgress)
                {
                    continue;
                }

                QueueOplockBreakNotification(openRecord, Smb2OplockLevel.None);
            }
        }

        private void QueueOplockBreakNotification(ServerOpenRecord openRecord, Smb2OplockLevel newOplockLevel)
        {
            openRecord.IsOplockBreakInProgress = true;
            openRecord.PendingOplockBreakLevel = newOplockLevel;

            Smb2OplockBreakNotification notification = new Smb2OplockBreakNotification
            {
                OplockLevel = newOplockLevel,
                PersistentFileId = openRecord.State.PersistentFileId,
                VolatileFileId = openRecord.State.VolatileFileId
            };
            Smb2OplockBreakNotificationValidator.Validate(notification);
            _EnqueueNotificationPayload(openRecord, notification.ToByteArray());
        }

        private void QueueLeaseBreakNotifications(IReadOnlyList<ServerOpenRecord> matchingOpens, ServerOpenRecord excludedOpenRecord)
        {
            HashSet<OpenCifsServerLeaseRecord> dispatchedLeases = new HashSet<OpenCifsServerLeaseRecord>();

            for (int index = 0; index < matchingOpens.Count; index++)
            {
                ServerOpenRecord openRecord = matchingOpens[index];
                OpenCifsServerLeaseRecord? leaseRecord = openRecord.LeaseRecord;

                if (leaseRecord == null ||
                    ReferenceEquals(openRecord, excludedOpenRecord) ||
                    ReferenceEquals(leaseRecord, excludedOpenRecord.LeaseRecord) ||
                    leaseRecord.LeaseState == Smb2LeaseState.None ||
                    leaseRecord.IsBreaking ||
                    !dispatchedLeases.Add(leaseRecord))
                {
                    continue;
                }

                QueueLeaseBreakNotification(openRecord, leaseRecord, Smb2LeaseState.None);
            }
        }

        private void QueueLeaseBreakNotification(ServerOpenRecord openRecord, OpenCifsServerLeaseRecord leaseRecord, Smb2LeaseState newLeaseState)
        {
            leaseRecord.IsBreaking = true;
            leaseRecord.PendingBreakLeaseState = newLeaseState;

            Smb2LeaseBreakNotification notification = new Smb2LeaseBreakNotification
            {
                NewEpoch = 0,
                Flags = Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired,
                LeaseKey = leaseRecord.LeaseKey,
                CurrentLeaseState = leaseRecord.LeaseState,
                NewLeaseState = newLeaseState,
                BreakReason = 0,
                AccessMaskHint = 0,
                ShareMaskHint = 0
            };
            Smb2LeaseBreakNotificationValidator.Validate(notification);
            _EnqueueNotificationPayload(openRecord, notification.ToByteArray());
        }
    }
}
