namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerDurableReconnectCreateOperationService
    {
        private readonly Func<string, OpenCifsServerLeaseRecord?, Smb2LeaseState, Smb2LeaseState> _DetermineGrantedCreateLeaseState;
        private readonly OpenCifsServerFileStateTracker _FileStateTracker;
        private readonly OpenCifsServerSharedState _SharedState;
        private readonly Action<OpenCifsServerLeaseRecord> _UpdateLeaseStateForTrackedOpens;

        public OpenCifsServerDurableReconnectCreateOperationService(
            OpenCifsServerSharedState sharedState,
            OpenCifsServerFileStateTracker fileStateTracker,
            Func<string, OpenCifsServerLeaseRecord?, Smb2LeaseState, Smb2LeaseState> determineGrantedCreateLeaseState,
            Action<OpenCifsServerLeaseRecord> updateLeaseStateForTrackedOpens)
        {
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _FileStateTracker = fileStateTracker ?? throw new ArgumentNullException(nameof(fileStateTracker), "FileStateTracker cannot be null.");
            _DetermineGrantedCreateLeaseState = determineGrantedCreateLeaseState ?? throw new ArgumentNullException(nameof(determineGrantedCreateLeaseState), "DetermineGrantedCreateLeaseState cannot be null.");
            _UpdateLeaseStateForTrackedOpens = updateLeaseStateForTrackedOpens ?? throw new ArgumentNullException(nameof(updateLeaseStateForTrackedOpens), "UpdateLeaseStateForTrackedOpens cannot be null.");
        }

        public OpenCifsServerOperationResult<Smb2CreateResponse> Execute(OpenCifsServerDurableReconnectCreateOperationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }

            if (context.Request.Name.Length == 0 ||
                (context.Request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            if (!_SharedState.TryTakeDetachedDurableOpen(context.PersistentFileId, out OpenCifsServerDurableOpenRecord? durableOpenRecord) ||
                durableOpenRecord == null)
            {
                return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
            }

            bool reconnectAccepted = false;

            try
            {
                if (!string.Equals(durableOpenRecord.DurableOwnerUserName, context.SessionRecord.UserName, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(durableOpenRecord.DurableOwnerUserDomain, context.SessionRecord.UserDomain, StringComparison.OrdinalIgnoreCase))
                {
                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }

                if (!string.Equals(durableOpenRecord.ShareName, context.TreeRecord.ShareName, StringComparison.OrdinalIgnoreCase) ||
                    !string.Equals(durableOpenRecord.FullPath, context.FullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }

                if (durableOpenRecord.Stream == null)
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }

                if (durableOpenRecord.UsesDurableHandleV2)
                {
                    if (!context.DurableCreateGuid.HasValue || context.DurableCreateGuid.Value == Guid.Empty)
                    {
                        return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                    }

                    if (durableOpenRecord.DurableCreateGuid != context.DurableCreateGuid.Value)
                    {
                        return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                    }
                }
                else if (context.DurableCreateGuid.HasValue)
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }

                OpenCifsServerLeaseRecord? attachedLeaseRecord = durableOpenRecord.LeaseRecord;

                if ((attachedLeaseRecord == null) != (context.LeaseRequestContext == null))
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }

                if (attachedLeaseRecord != null)
                {
                    if (attachedLeaseRecord.ClientGuid != context.NegotiatedClientGuid ||
                        context.LeaseRequestContext == null ||
                        !attachedLeaseRecord.LeaseKey.AsSpan().SequenceEqual(context.LeaseRequestContext.LeaseKey) ||
                        !OpenCifsServerLeaseStateHelper.SupportsDurableReconnect(attachedLeaseRecord.LeaseState))
                    {
                        return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                    }
                }
                else if (durableOpenRecord.GrantedOplockLevel != Smb2OplockLevel.Batch)
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }

                ulong newVolatileFileId = _SharedState.AllocateFileId();
                OpenState openState = new OpenState();
                openState.Bind(durableOpenRecord.PersistentFileId, newVolatileFileId, durableOpenRecord.RelativePath);
                openState.SetDeletePending(durableOpenRecord.IsDeletePending);
                openState.SetOplockLevel(durableOpenRecord.GrantedOplockLevel);
                openState.SetDurable(
                    true,
                    durableOpenRecord.UsesDurableHandleV2,
                    durableOpenRecord.DurableCreateGuid,
                    durableOpenRecord.DurableTimeoutMs,
                    durableOpenRecord.IsPersistent);
                bool leaseBreakInProgress = attachedLeaseRecord != null && attachedLeaseRecord.IsBreaking;

                if (attachedLeaseRecord != null)
                {
                    attachedLeaseRecord.FullPath = context.FullPath;
                    attachedLeaseRecord.LeaseState = _DetermineGrantedCreateLeaseState(context.FullPath, attachedLeaseRecord, attachedLeaseRecord.LeaseState);

                    if (!leaseBreakInProgress)
                    {
                        attachedLeaseRecord.PendingBreakLeaseState = attachedLeaseRecord.LeaseState;
                    }

                    openState.SetLease(attachedLeaseRecord.LeaseKey, attachedLeaseRecord.LeaseState);
                }

                ServerOpenRecord openRecord = new ServerOpenRecord
                {
                    OwnerHost = context.OwnerHost,
                    SessionId = context.SessionRecord.State.SessionId,
                    TreeId = context.TreeRecord.State.TreeId,
                    ShareName = context.TreeRecord.ShareName,
                    ShareRootPath = context.TreeRecord.ShareRootPath,
                    Backend = context.TreeRecord.Backend,
                    FullPath = durableOpenRecord.FullPath,
                    DesiredAccess = durableOpenRecord.DesiredAccess,
                    ShareAccess = durableOpenRecord.ShareAccess,
                    CanRead = durableOpenRecord.CanRead,
                    CanWrite = durableOpenRecord.CanWrite,
                    CanReadData = durableOpenRecord.CanReadData,
                    CanWriteData = durableOpenRecord.CanWriteData,
                    CanDelete = durableOpenRecord.CanDelete,
                    IsDirectory = false,
                    GrantedOplockLevel = durableOpenRecord.GrantedOplockLevel,
                    PendingOplockBreakLevel = durableOpenRecord.GrantedOplockLevel,
                    LeaseRecord = attachedLeaseRecord,
                    Stream = durableOpenRecord.Stream,
                    State = openState,
                    SuppressAccessTimeUpdates = durableOpenRecord.SuppressAccessTimeUpdates,
                    SuppressModificationTimeUpdates = durableOpenRecord.SuppressModificationTimeUpdates,
                    SuppressChangeTimeUpdates = durableOpenRecord.SuppressChangeTimeUpdates
                };

                for (int index = 0; index < durableOpenRecord.Locks.Count; index++)
                {
                    OpenCifsServerDetachedByteRangeLock detachedLock = durableOpenRecord.Locks[index];
                    openRecord.Locks.Add(new ServerByteRangeLock
                    {
                        OwnerVolatileFileId = newVolatileFileId,
                        Offset = detachedLock.Offset,
                        Length = detachedLock.Length,
                        IsShared = detachedLock.IsShared
                    });
                }

                durableOpenRecord.Stream = null;
                context.SessionRecord.Opens[newVolatileFileId] = openRecord;

                if (attachedLeaseRecord != null)
                {
                    _UpdateLeaseStateForTrackedOpens(attachedLeaseRecord);
                }

                FileMetadata metadata = _FileStateTracker.BuildFileMetadata(context.TreeRecord.Backend, context.FullPath);
                List<Smb2CreateContext> responseCreateContexts = new List<Smb2CreateContext>
                {
                    durableOpenRecord.UsesDurableHandleV2
                        ? new Smb2DurableHandleResponseV2Context
                        {
                            Timeout = durableOpenRecord.DurableTimeoutMs,
                            Flags = durableOpenRecord.IsPersistent ? Smb2DurableHandleFlags.Persistent : Smb2DurableHandleFlags.None
                        }.ToCreateContext()
                        : Smb2DurableHandleResponseContext.Create()
                };

                if (attachedLeaseRecord != null)
                {
                    responseCreateContexts.Add(new Smb2CreateResponseLeaseContext
                    {
                        LeaseKey = attachedLeaseRecord.LeaseKey,
                        LeaseState = attachedLeaseRecord.LeaseState,
                        LeaseFlags = leaseBreakInProgress ? Smb2LeaseFlags.BreakInProgress : Smb2LeaseFlags.None
                    }.ToCreateContext());
                }

                Smb2CreateResponse response = new Smb2CreateResponse
                {
                    OplockLevel = durableOpenRecord.GrantedOplockLevel,
                    Flags = 0,
                    CreateAction = Smb2CreateAction.Opened,
                    CreationTime = metadata.CreationTime,
                    LastAccessTime = metadata.LastAccessTime,
                    LastWriteTime = metadata.LastWriteTime,
                    ChangeTime = metadata.ChangeTime,
                    AllocationSize = metadata.AllocationSize,
                    EndOfFile = metadata.EndOfFile,
                    FileAttributes = metadata.FileAttributes,
                    PersistentFileId = durableOpenRecord.PersistentFileId,
                    VolatileFileId = newVolatileFileId,
                    CreateContexts = Smb2CreateContextCodec.Encode(responseCreateContexts)
                };
                Smb2CreateResponseValidator.Validate(response);
                reconnectAccepted = true;
                return CreateOperationResult(NtStatus.Success, response);
            }
            finally
            {
                if (!reconnectAccepted)
                {
                    _SharedState.PutDetachedDurableOpen(durableOpenRecord);
                }
            }
        }

        private static OpenCifsServerOperationResult<Smb2CreateResponse> CreateOperationResult(NtStatus status, Smb2CreateResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2CreateResponse>
            {
                Status = status,
                Response = response
            };
        }
    }
}
