namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal sealed class OpenCifsServerRegularCreateOperationService
    {
        private readonly OpenCifsServerBreakNotificationDispatcher _BreakNotificationDispatcher;
        private readonly Action<ServerSessionRecord, ulong> _CloseOpenRecord;
        private readonly Func<string, OpenCifsServerLeaseRecord?, Smb2LeaseState, Smb2LeaseState> _DetermineGrantedCreateLeaseState;
        private readonly Func<Smb2CreateRequest, bool, string, Smb2OplockLevel> _DetermineGrantedCreateOplockLevel;
        private readonly Func<OpenCifsServerShareBackend, string, bool> _DeleteBackingObjectIfPresent;
        private readonly OpenCifsServerFileStateTracker _FileStateTracker;
        private readonly Func<uint, uint> _GetGrantedDurableHandleTimeoutMs;
        private readonly OpenCifsServerOpenStateTracker _OpenStateTracker;
        private readonly Action<string, FileNotifyChangeFilter> _PublishModifiedNotification;
        private readonly Action<string, bool, FileNotifyAction> _PublishNameChangeNotification;
        private readonly OpenCifsServerSetInfoMutationService _SetInfoMutationService;
        private readonly OpenCifsServerSharedState _SharedState;
        private readonly Action<OpenCifsServerLeaseRecord> _UpdateLeaseStateForTrackedOpens;

        public OpenCifsServerRegularCreateOperationService(
            OpenCifsServerSharedState sharedState,
            OpenCifsServerOpenStateTracker openStateTracker,
            OpenCifsServerFileStateTracker fileStateTracker,
            OpenCifsServerSetInfoMutationService setInfoMutationService,
            OpenCifsServerBreakNotificationDispatcher breakNotificationDispatcher,
            Func<string, OpenCifsServerLeaseRecord?, Smb2LeaseState, Smb2LeaseState> determineGrantedCreateLeaseState,
            Func<Smb2CreateRequest, bool, string, Smb2OplockLevel> determineGrantedCreateOplockLevel,
            Func<uint, uint> getGrantedDurableHandleTimeoutMs,
            Action<OpenCifsServerLeaseRecord> updateLeaseStateForTrackedOpens,
            Action<ServerSessionRecord, ulong> closeOpenRecord,
            Func<OpenCifsServerShareBackend, string, bool> deleteBackingObjectIfPresent,
            Action<string, bool, FileNotifyAction> publishNameChangeNotification,
            Action<string, FileNotifyChangeFilter> publishModifiedNotification)
        {
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _OpenStateTracker = openStateTracker ?? throw new ArgumentNullException(nameof(openStateTracker), "OpenStateTracker cannot be null.");
            _FileStateTracker = fileStateTracker ?? throw new ArgumentNullException(nameof(fileStateTracker), "FileStateTracker cannot be null.");
            _SetInfoMutationService = setInfoMutationService ?? throw new ArgumentNullException(nameof(setInfoMutationService), "SetInfoMutationService cannot be null.");
            _BreakNotificationDispatcher = breakNotificationDispatcher ?? throw new ArgumentNullException(nameof(breakNotificationDispatcher), "BreakNotificationDispatcher cannot be null.");
            _DetermineGrantedCreateLeaseState = determineGrantedCreateLeaseState ?? throw new ArgumentNullException(nameof(determineGrantedCreateLeaseState), "DetermineGrantedCreateLeaseState cannot be null.");
            _DetermineGrantedCreateOplockLevel = determineGrantedCreateOplockLevel ?? throw new ArgumentNullException(nameof(determineGrantedCreateOplockLevel), "DetermineGrantedCreateOplockLevel cannot be null.");
            _GetGrantedDurableHandleTimeoutMs = getGrantedDurableHandleTimeoutMs ?? throw new ArgumentNullException(nameof(getGrantedDurableHandleTimeoutMs), "GetGrantedDurableHandleTimeoutMs cannot be null.");
            _UpdateLeaseStateForTrackedOpens = updateLeaseStateForTrackedOpens ?? throw new ArgumentNullException(nameof(updateLeaseStateForTrackedOpens), "UpdateLeaseStateForTrackedOpens cannot be null.");
            _CloseOpenRecord = closeOpenRecord ?? throw new ArgumentNullException(nameof(closeOpenRecord), "CloseOpenRecord cannot be null.");
            _DeleteBackingObjectIfPresent = deleteBackingObjectIfPresent ?? throw new ArgumentNullException(nameof(deleteBackingObjectIfPresent), "DeleteBackingObjectIfPresent cannot be null.");
            _PublishNameChangeNotification = publishNameChangeNotification ?? throw new ArgumentNullException(nameof(publishNameChangeNotification), "PublishNameChangeNotification cannot be null.");
            _PublishModifiedNotification = publishModifiedNotification ?? throw new ArgumentNullException(nameof(publishModifiedNotification), "PublishModifiedNotification cannot be null.");
        }

        public OpenCifsServerOperationResult<Smb2CreateResponse> Execute(OpenCifsServerRegularCreateOperationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }

            bool existsDirectory = context.TreeRecord.Backend.DirectoryExists(context.FullPath);
            bool existsFile = context.TreeRecord.Backend.FileExists(context.FullPath);
            bool isDirectoryRequest = context.IsShareRootOpenRequest ||
                (context.Request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0 ||
                (existsDirectory && (context.Request.CreateOptions & Smb2CreateOptions.NonDirectoryFile) == 0);

            if (!isDirectoryRequest && existsDirectory)
            {
                return CreateOperationResult(NtStatus.FileIsADirectory, new Smb2CreateResponse());
            }

            if (isDirectoryRequest && existsFile)
            {
                NtStatus fileTypeStatus = context.Request.CreateDisposition == Smb2CreateDisposition.Create
                    ? NtStatus.ObjectNameCollision
                    : NtStatus.NotADirectory;
                return CreateOperationResult(fileTypeStatus, new Smb2CreateResponse());
            }

            string? parentDirectory = Path.GetDirectoryName(context.FullPath);

            if (string.IsNullOrEmpty(parentDirectory) || !context.TreeRecord.Backend.DirectoryExists(parentDirectory))
            {
                return CreateOperationResult(NtStatus.ObjectPathNotFound, new Smb2CreateResponse());
            }

            bool exists = isDirectoryRequest ? existsDirectory : existsFile;
            bool requiresWriteAccessForOpen = !isDirectoryRequest &&
                (context.Request.CreateDisposition == Smb2CreateDisposition.Create ||
                 context.Request.CreateDisposition == Smb2CreateDisposition.OpenIf ||
                 context.Request.CreateDisposition == Smb2CreateDisposition.Overwrite ||
                 context.Request.CreateDisposition == Smb2CreateDisposition.OverwriteIf ||
                 context.Request.CreateDisposition == Smb2CreateDisposition.Supersede);
            bool canWrite = OpenCifsServerFilePolicy.CanWrite(context.Request.DesiredAccess);
            bool canRead = OpenCifsServerFilePolicy.CanRead(context.Request.DesiredAccess);
            bool canWriteData = OpenCifsServerFilePolicy.CanWriteData(context.Request.DesiredAccess);
            bool canReadData = OpenCifsServerFilePolicy.CanReadData(context.Request.DesiredAccess);
            bool canDelete = OpenCifsServerFilePolicy.CanDelete(context.Request.DesiredAccess);
            bool deleteOnClose = (context.Request.CreateOptions & Smb2CreateOptions.DeleteOnClose) != 0;
            bool leaseRequested = !isDirectoryRequest &&
                context.Request.RequestedOplockLevel == Smb2OplockLevel.Lease &&
                context.LeaseRequestContext != null &&
                context.NegotiatedDialect.HasValue &&
                context.NegotiatedDialect.Value >= SmbDialect.Smb21;
            OpenCifsServerLeaseRecord? existingLeaseRecord = null;
            Smb2LeaseState grantedLeaseState = Smb2LeaseState.None;
            bool leaseBreakInProgress = false;

            if (leaseRequested)
            {
                _SharedState.TryGetLeaseRecord(context.NegotiatedClientGuid, context.LeaseRequestContext!.LeaseKey, out existingLeaseRecord);

                if (existingLeaseRecord != null &&
                    !string.Equals(existingLeaseRecord.FullPath, context.FullPath, StringComparison.OrdinalIgnoreCase))
                {
                    return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }

                grantedLeaseState = _DetermineGrantedCreateLeaseState(
                    context.FullPath,
                    existingLeaseRecord,
                    OpenCifsServerLeaseStateHelper.Normalize(context.LeaseRequestContext.LeaseState));
                leaseBreakInProgress = existingLeaseRecord != null && existingLeaseRecord.IsBreaking;
            }

            Smb2OplockLevel grantedOplockLevel = leaseRequested
                ? Smb2OplockLevel.Lease
                : _DetermineGrantedCreateOplockLevel(context.Request, isDirectoryRequest, context.FullPath);

            if (requiresWriteAccessForOpen && !canWrite)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
            }

            if (!_OpenStateTracker.TryValidateCreateOpenSemantics(context.FullPath, context.Request.DesiredAccess, context.Request.ShareAccess, out NtStatus openStatus))
            {
                return CreateOperationResult(openStatus, new Smb2CreateResponse());
            }

            FileMode fileMode;
            Smb2CreateAction createAction;

            if (isDirectoryRequest)
            {
                switch (context.Request.CreateDisposition)
                {
                    case Smb2CreateDisposition.Create:
                        if (exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameCollision, new Smb2CreateResponse());
                        }

                        if (!OpenCifsServerPathResolver.TryCreateBackingDirectory(context.TreeRecord.Backend, context.FullPath, out NtStatus directoryCreateStatus))
                        {
                            return CreateOperationResult(directoryCreateStatus, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Open;
                        createAction = Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.Open:
                        if (!exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Open;
                        createAction = Smb2CreateAction.Opened;
                        break;
                    case Smb2CreateDisposition.OpenIf:
                        if (!exists)
                        {
                            if (!OpenCifsServerPathResolver.TryCreateBackingDirectory(context.TreeRecord.Backend, context.FullPath, out NtStatus directoryOpenIfStatus))
                            {
                                return CreateOperationResult(directoryOpenIfStatus, new Smb2CreateResponse());
                            }

                            createAction = Smb2CreateAction.Created;
                        }
                        else
                        {
                            createAction = Smb2CreateAction.Opened;
                        }

                        fileMode = FileMode.Open;
                        break;
                    default:
                        return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }
            }
            else
            {
                switch (context.Request.CreateDisposition)
                {
                    case Smb2CreateDisposition.Supersede:
                        fileMode = FileMode.Create;
                        createAction = exists ? Smb2CreateAction.Superseded : Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.Open:
                        if (!exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Open;
                        createAction = Smb2CreateAction.Opened;
                        break;
                    case Smb2CreateDisposition.Create:
                        if (exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameCollision, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.CreateNew;
                        createAction = Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.OpenIf:
                        fileMode = FileMode.OpenOrCreate;
                        createAction = exists ? Smb2CreateAction.Opened : Smb2CreateAction.Created;
                        break;
                    case Smb2CreateDisposition.Overwrite:
                        if (!exists)
                        {
                            return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                        }

                        fileMode = FileMode.Truncate;
                        createAction = Smb2CreateAction.Overwritten;
                        break;
                    case Smb2CreateDisposition.OverwriteIf:
                        fileMode = FileMode.Create;
                        createAction = exists ? Smb2CreateAction.Overwritten : Smb2CreateAction.Created;
                        break;
                    default:
                        return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
                }
            }

            if (createAction == Smb2CreateAction.Created &&
                deleteOnClose &&
                (context.Request.FileAttributes & ProtocolFileAttributes.ReadOnly) != 0)
            {
                if (isDirectoryRequest && !exists)
                {
                    _DeleteBackingObjectIfPresent(context.TreeRecord.Backend, context.FullPath);
                }

                return CreateOperationResult(NtStatus.CannotDelete, new Smb2CreateResponse());
            }

            FileAccess fileAccess = OpenCifsServerFilePolicy.DetermineFileAccess(context.Request.DesiredAccess);
            FileStream? stream = null;
            bool shouldApplyCreateFileAttributes = !isDirectoryRequest &&
                (createAction == Smb2CreateAction.Created ||
                 createAction == Smb2CreateAction.Overwritten ||
                 createAction == Smb2CreateAction.Superseded);

            if (!isDirectoryRequest)
            {
                try
                {
                    stream = context.TreeRecord.Backend.OpenFile(context.FullPath, fileMode, fileAccess, FileShare.ReadWrite | FileShare.Delete);
                }
                catch (DirectoryNotFoundException)
                {
                    return CreateOperationResult(NtStatus.ObjectPathNotFound, new Smb2CreateResponse());
                }
                catch (FileNotFoundException)
                {
                    return CreateOperationResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
                }
                catch (UnauthorizedAccessException)
                {
                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
                catch (IOException)
                {
                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
            }

            if (shouldApplyCreateFileAttributes)
            {
                try
                {
                    context.TreeRecord.Backend.SetAttributes(context.FullPath, OpenCifsServerFilePolicy.NormalizeCreateFileAttributes(context.Request.FileAttributes));
                }
                catch (UnauthorizedAccessException)
                {
                    stream?.Dispose();

                    if (createAction == Smb2CreateAction.Created)
                    {
                        _DeleteBackingObjectIfPresent(context.TreeRecord.Backend, context.FullPath);
                    }

                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
                catch (IOException)
                {
                    stream?.Dispose();

                    if (createAction == Smb2CreateAction.Created)
                    {
                        _DeleteBackingObjectIfPresent(context.TreeRecord.Backend, context.FullPath);
                    }

                    return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
                }
            }

            bool durableHandleGranted = context.DurableHandleRequested &&
                !isDirectoryRequest &&
                (grantedOplockLevel == Smb2OplockLevel.Batch ||
                 (leaseRequested && context.LeaseRequestContext != null && OpenCifsServerLeaseStateHelper.SupportsDurableReconnect(context.LeaseRequestContext.LeaseState)));
            bool durableHandleV2Granted = durableHandleGranted && context.DurableHandleRequestV2Context != null;
            uint grantedDurableTimeoutMs = durableHandleGranted
                ? _GetGrantedDurableHandleTimeoutMs(context.DurableHandleRequestV2Context?.Timeout ?? 0)
                : 0;
            ulong fileId = _SharedState.AllocateFileId();
            OpenState openState = new OpenState();
            openState.Bind(fileId, fileId, context.Request.Name.Length == 0 ? "\\" : context.Request.Name);
            openState.SetOplockLevel(grantedOplockLevel);
            openState.SetDurable(
                durableHandleGranted,
                durableHandleV2Granted,
                context.DurableHandleRequestV2Context?.CreateGuid ?? Guid.Empty,
                grantedDurableTimeoutMs,
                isPersistent: false);
            OpenCifsServerLeaseRecord? attachedLeaseRecord = null;

            if (leaseRequested && context.LeaseRequestContext != null)
            {
                attachedLeaseRecord = existingLeaseRecord ?? _SharedState.GetOrAddLeaseRecord(context.NegotiatedClientGuid, context.LeaseRequestContext.LeaseKey, context.FullPath);
                attachedLeaseRecord.FullPath = context.FullPath;
                attachedLeaseRecord.LeaseState = grantedLeaseState;

                if (!leaseBreakInProgress)
                {
                    attachedLeaseRecord.PendingBreakLeaseState = grantedLeaseState;
                }

                attachedLeaseRecord.OpenCount++;
                openState.SetLease(attachedLeaseRecord.LeaseKey, grantedLeaseState);
            }

            ServerOpenRecord openRecord = new ServerOpenRecord
            {
                OwnerHost = context.OwnerHost,
                SessionId = context.SessionId,
                TreeId = context.TreeId,
                ShareName = context.TreeRecord.ShareName,
                ShareRootPath = context.TreeRecord.ShareRootPath,
                Backend = context.TreeRecord.Backend,
                FullPath = context.FullPath,
                DesiredAccess = context.Request.DesiredAccess,
                ShareAccess = context.Request.ShareAccess,
                CanRead = canRead,
                CanWrite = canWrite,
                CanReadData = canReadData,
                CanWriteData = canWriteData,
                CanDelete = canDelete,
                IsDirectory = isDirectoryRequest,
                GrantedOplockLevel = grantedOplockLevel,
                PendingOplockBreakLevel = grantedOplockLevel,
                LeaseRecord = attachedLeaseRecord,
                Stream = stream,
                State = openState
            };
            context.SessionRecord.Opens[fileId] = openRecord;

            if (attachedLeaseRecord != null)
            {
                _UpdateLeaseStateForTrackedOpens(attachedLeaseRecord);
            }

            if (deleteOnClose)
            {
                NtStatus deletePendingStatus = _SetInfoMutationService.ApplyDeletePendingState(openRecord, deletePending: true);

                if (deletePendingStatus != NtStatus.Success)
                {
                    _CloseOpenRecord(context.SessionRecord, fileId);
                    return CreateOperationResult(deletePendingStatus, new Smb2CreateResponse());
                }
            }

            if (!isDirectoryRequest && stream != null)
            {
                ulong currentLength = unchecked((ulong)Math.Max(0L, stream.Length));

                if (createAction == Smb2CreateAction.Opened)
                {
                    _FileStateTracker.EnsureDeclaredAllocationSize(context.FullPath, currentLength);
                }
                else
                {
                    _FileStateTracker.SetDeclaredAllocationSize(context.FullPath, currentLength, currentLength);
                }
            }

            FileMetadata metadata = _FileStateTracker.BuildFileMetadata(context.TreeRecord.Backend, context.FullPath);
            List<Smb2CreateContext> responseCreateContexts = new List<Smb2CreateContext>();

            if (durableHandleGranted)
            {
                responseCreateContexts.Add(durableHandleV2Granted
                    ? new Smb2DurableHandleResponseV2Context
                    {
                        Timeout = grantedDurableTimeoutMs,
                        Flags = Smb2DurableHandleFlags.None
                    }.ToCreateContext()
                    : Smb2DurableHandleResponseContext.Create());
            }

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
                OplockLevel = grantedOplockLevel,
                Flags = 0,
                CreateAction = createAction,
                CreationTime = metadata.CreationTime,
                LastAccessTime = metadata.LastAccessTime,
                LastWriteTime = metadata.LastWriteTime,
                ChangeTime = metadata.ChangeTime,
                AllocationSize = metadata.AllocationSize,
                EndOfFile = metadata.EndOfFile,
                FileAttributes = metadata.FileAttributes,
                PersistentFileId = fileId,
                VolatileFileId = fileId,
                CreateContexts = responseCreateContexts.Count == 0
                    ? Array.Empty<byte>()
                    : Smb2CreateContextCodec.Encode(responseCreateContexts)
            };

            Smb2CreateResponseValidator.Validate(response);

            if (createAction == Smb2CreateAction.Created)
            {
                _PublishNameChangeNotification(context.FullPath, isDirectoryRequest, FileNotifyAction.Added);
            }
            else if (createAction == Smb2CreateAction.Overwritten || createAction == Smb2CreateAction.Superseded)
            {
                _PublishModifiedNotification(
                    context.FullPath,
                    FileNotifyChangeFilter.Size |
                    FileNotifyChangeFilter.LastWrite |
                    FileNotifyChangeFilter.Creation |
                    (shouldApplyCreateFileAttributes ? FileNotifyChangeFilter.Attributes : FileNotifyChangeFilter.None));
            }

            if (!isDirectoryRequest)
            {
                _BreakNotificationDispatcher.QueueBreakNotificationsForConflictingOpens(context.FullPath, openRecord);
            }

            return CreateOperationResult(NtStatus.Success, response);
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
