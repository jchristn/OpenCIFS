namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerBreakAcknowledgmentService
    {
        private readonly Action<OpenCifsServerLeaseRecord> _UpdateLeaseStateForTrackedOpens;

        public OpenCifsServerBreakAcknowledgmentService(Action<OpenCifsServerLeaseRecord> updateLeaseStateForTrackedOpens)
        {
            _UpdateLeaseStateForTrackedOpens = updateLeaseStateForTrackedOpens ?? throw new ArgumentNullException(nameof(updateLeaseStateForTrackedOpens), "UpdateLeaseStateForTrackedOpens cannot be null.");
        }

        public OpenCifsServerOperationResult<Smb2OplockBreakResponse> ApplyOplockBreakAcknowledgment(
            ServerOpenRecord openRecord,
            Smb2OplockBreakAcknowledgment request)
        {
            if (openRecord == null)
            {
                throw new ArgumentNullException(nameof(openRecord), "OpenRecord cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (!openRecord.IsOplockBreakInProgress)
            {
                return CreateOplockResult(NtStatus.InvalidDeviceState, new Smb2OplockBreakResponse());
            }

            if (request.OplockLevel != openRecord.PendingOplockBreakLevel)
            {
                return CreateOplockResult(NtStatus.InvalidOplockProtocol, new Smb2OplockBreakResponse());
            }

            openRecord.GrantedOplockLevel = request.OplockLevel;
            openRecord.PendingOplockBreakLevel = request.OplockLevel;
            openRecord.IsOplockBreakInProgress = false;

            Smb2OplockBreakResponse response = new Smb2OplockBreakResponse
            {
                OplockLevel = openRecord.GrantedOplockLevel,
                PersistentFileId = openRecord.State.PersistentFileId,
                VolatileFileId = openRecord.State.VolatileFileId
            };
            Smb2OplockBreakResponseValidator.Validate(response);
            return CreateOplockResult(NtStatus.Success, response);
        }

        public OpenCifsServerOperationResult<Smb2LeaseBreakResponse> ApplyLeaseBreakAcknowledgment(
            OpenCifsServerLeaseRecord leaseRecord,
            Smb2LeaseBreakAcknowledgment request)
        {
            if (leaseRecord == null)
            {
                throw new ArgumentNullException(nameof(leaseRecord), "LeaseRecord cannot be null.");
            }

            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            if (!leaseRecord.IsBreaking)
            {
                return CreateLeaseResult(NtStatus.InvalidDeviceState, new Smb2LeaseBreakResponse());
            }

            Smb2LeaseState normalizedLeaseState = OpenCifsServerLeaseStateHelper.Normalize(request.LeaseState);

            if (normalizedLeaseState != leaseRecord.PendingBreakLeaseState)
            {
                return CreateLeaseResult(NtStatus.InvalidOplockProtocol, new Smb2LeaseBreakResponse());
            }

            leaseRecord.LeaseState = normalizedLeaseState;
            leaseRecord.PendingBreakLeaseState = leaseRecord.LeaseState;
            leaseRecord.IsBreaking = false;
            _UpdateLeaseStateForTrackedOpens(leaseRecord);

            Smb2LeaseBreakResponse response = new Smb2LeaseBreakResponse
            {
                LeaseKey = leaseRecord.LeaseKey,
                LeaseState = leaseRecord.LeaseState
            };
            Smb2LeaseBreakResponseValidator.Validate(response);
            return CreateLeaseResult(NtStatus.Success, response);
        }

        private static OpenCifsServerOperationResult<Smb2OplockBreakResponse> CreateOplockResult(NtStatus status, Smb2OplockBreakResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2OplockBreakResponse>
            {
                Status = status,
                Response = response
            };
        }

        private static OpenCifsServerOperationResult<Smb2LeaseBreakResponse> CreateLeaseResult(NtStatus status, Smb2LeaseBreakResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2LeaseBreakResponse>
            {
                Status = status,
                Response = response
            };
        }
    }
}
