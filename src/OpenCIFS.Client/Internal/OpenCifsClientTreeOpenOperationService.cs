namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientTreeOpenOperationService
    {
        private const uint DefaultShareAccess = 0x00000007U;

        public OpenCifsClientTreeOpenOperationService(
            IDictionary<uint, OpenCifsClientTreeHandle> activeTreesById,
            IDictionary<string, OpenCifsClientOpenHandle> activeOpensByKey,
            Guid connectionId,
            Func<long> getSessionGeneration,
            Func<OpenCifsClientSession> getSession,
            Action ensureAuthenticatedSession,
            Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> sendSingleRequestAsync,
            Func<CancellationToken, Task<byte[]>> readNextResponsePacketBytesAsync,
            Func<Smb2CompoundPacketEntry, byte[]> getResponsePayloadBytes)
        {
            _ActiveTreesById = activeTreesById ?? throw new ArgumentNullException(nameof(activeTreesById), "ActiveTreesById cannot be null.");
            _ActiveOpensByKey = activeOpensByKey ?? throw new ArgumentNullException(nameof(activeOpensByKey), "ActiveOpensByKey cannot be null.");
            _ConnectionId = connectionId;
            _GetSessionGeneration = getSessionGeneration ?? throw new ArgumentNullException(nameof(getSessionGeneration), "GetSessionGeneration cannot be null.");
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
            _EnsureAuthenticatedSession = ensureAuthenticatedSession ?? throw new ArgumentNullException(nameof(ensureAuthenticatedSession), "EnsureAuthenticatedSession cannot be null.");
            _SendSingleRequestAsync = sendSingleRequestAsync ?? throw new ArgumentNullException(nameof(sendSingleRequestAsync), "SendSingleRequestAsync cannot be null.");
            _ReadNextResponsePacketBytesAsync = readNextResponsePacketBytesAsync ?? throw new ArgumentNullException(nameof(readNextResponsePacketBytesAsync), "ReadNextResponsePacketBytesAsync cannot be null.");
            _GetResponsePayloadBytes = getResponsePayloadBytes ?? throw new ArgumentNullException(nameof(getResponsePayloadBytes), "GetResponsePayloadBytes cannot be null.");
        }

        public OpenCifsClientTreeHandle CreateTrackedTreeHandle(string shareName, uint treeId, Smb2ShareFlags shareFlags)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            OpenCifsClientTreeHandle handle = new OpenCifsClientTreeHandle(
                _ConnectionId,
                _GetSessionGeneration(),
                shareName,
                treeId,
                shareFlags);
            _ActiveTreesById[handle.TreeId] = handle;
            return handle;
        }

        public async Task<OpenCifsClientOpenHandle> OpenAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            CancellationToken cancellationToken,
            Smb2OplockLevel requestedOplockLevel,
            bool requestDurableHandle,
            Smb2LeaseState requestedLeaseState,
            byte[]? leaseKey)
        {
            ValidateTreeHandle(treeHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2OplockLevel effectiveOplockLevel = requestDurableHandle && requestedOplockLevel == Smb2OplockLevel.None
                ? Smb2OplockLevel.Batch
                : requestedOplockLevel;
            Smb2CreateRequest request = session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                effectiveOplockLevel,
                requestDurableHandle,
                requestedLeaseState,
                leaseKey);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(
                requestHeader,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            Smb2CreateResponse createResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                responseEnvelope.ResponseHeader.Status,
                responseEnvelope.ResponsePayload,
                Smb2CreateResponse.ReadFrom);
            return CreateOpenHandle(
                session,
                treeHandle,
                path,
                responseEnvelope.ResponseHeader,
                createResponse,
                request,
                (createOptions & Smb2CreateOptions.DirectoryFile) != 0,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                effectiveOplockLevel);
        }

        public async Task<OpenCifsClientOpenHandle> OpenExistingPathAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess,
            CancellationToken cancellationToken,
            Smb2OplockLevel requestedOplockLevel,
            bool requestDurableHandle,
            Smb2LeaseState requestedLeaseState,
            byte[]? leaseKey)
        {
            ValidateTreeHandle(treeHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2OplockLevel effectiveOplockLevel = requestDurableHandle && requestedOplockLevel == Smb2OplockLevel.None
                ? Smb2OplockLevel.Batch
                : requestedOplockLevel;
            OpenCifsClientRequestResponse responseEnvelope = await SendOpenExistingCreateAsync(
                treeHandle,
                path,
                desiredAccess,
                Smb2CreateOptions.NonDirectoryFile,
                cancellationToken,
                effectiveOplockLevel,
                requestDurableHandle,
                requestedLeaseState,
                leaseKey).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;
            bool isDirectory = false;
            Smb2CreateOptions appliedCreateOptions = Smb2CreateOptions.NonDirectoryFile;

            if (responseHeader.Status == NtStatus.FileIsADirectory)
            {
                OpenCifsClientRequestResponse directoryResponseEnvelope = await SendOpenExistingCreateAsync(
                    treeHandle,
                    path,
                    desiredAccess,
                    Smb2CreateOptions.DirectoryFile,
                    cancellationToken,
                    effectiveOplockLevel,
                    requestDurableHandle,
                    requestedLeaseState,
                    leaseKey).ConfigureAwait(false);
                responseHeader = directoryResponseEnvelope.ResponseHeader;
                responsePayload = directoryResponseEnvelope.ResponsePayload;
                isDirectory = true;
                appliedCreateOptions = Smb2CreateOptions.DirectoryFile;
            }

            Smb2CreateResponse createResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(responseHeader.Status, responsePayload, Smb2CreateResponse.ReadFrom);
            return CreateOpenHandle(
                session,
                treeHandle,
                path,
                responseHeader,
                createResponse,
                null,
                isDirectory,
                desiredAccess,
                FileAttributes.Normal,
                DefaultShareAccess,
                Smb2CreateDisposition.Open,
                appliedCreateOptions,
                effectiveOplockLevel);
        }

        public async Task<OpenCifsClientOpenHandle> ReconnectDurableOpenAsync(
            OpenCifsClientTreeHandle treeHandle,
            OpenCifsClientOpenHandle durableOpenHandle,
            CancellationToken cancellationToken)
        {
            ValidateTreeHandle(treeHandle);

            if (durableOpenHandle == null)
            {
                throw new ArgumentNullException(nameof(durableOpenHandle), "DurableOpenHandle cannot be null.");
            }

            if (!durableOpenHandle.CanReconnectDurably)
            {
                throw new OpenCifsClientStateException("The specified open handle is not currently usable as a durable reconnect token.");
            }

            if (durableOpenHandle.IsDirectory)
            {
                throw new OpenCifsClientStateException("Durable reconnect is bounded to file opens in the current managed slice.");
            }

            OpenCifsClientSession session = _GetSession();
            Smb2CreateRequest request = session.CreateDurableReconnectCreateRequest(
                treeHandle.TreeId,
                durableOpenHandle.Path,
                durableOpenHandle.PersistentFileId,
                durableOpenHandle.VolatileFileId,
                durableOpenHandle.DesiredAccess,
                durableOpenHandle.FileAttributes,
                durableOpenHandle.ShareAccess,
                durableOpenHandle.CreateDisposition,
                durableOpenHandle.CreateOptions,
                durableOpenHandle.RequestedOplockLevel,
                durableOpenHandle.LeaseState,
                durableOpenHandle.LeaseKey.Length == 16 ? durableOpenHandle.LeaseKey : null,
                durableOpenHandle.DurableCreateGuid,
                durableOpenHandle.UsesDurableHandleV2);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(
                requestHeader,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            Smb2CreateResponse createResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                responseEnvelope.ResponseHeader.Status,
                responseEnvelope.ResponsePayload,
                Smb2CreateResponse.ReadFrom);
            durableOpenHandle.MarkClosed();
            durableOpenHandle.InvalidateDurableReconnect();
            return CreateOpenHandle(
                session,
                treeHandle,
                durableOpenHandle.Path,
                responseEnvelope.ResponseHeader,
                createResponse,
                request,
                isDirectory: false,
                durableOpenHandle.DesiredAccess,
                durableOpenHandle.FileAttributes,
                durableOpenHandle.ShareAccess,
                durableOpenHandle.CreateDisposition,
                durableOpenHandle.CreateOptions,
                durableOpenHandle.RequestedOplockLevel);
        }

        public async Task<OpenCifsClientOplockBreakNotification> WaitForOplockBreakAsync(CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            OpenCifsClientSession session = _GetSession();
            byte[] responseBytes = await _ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
            session.ValidateOplockBreakNotificationPacket(responsePacket, responseBytes);
            Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];
            Smb2OplockBreakNotification notification = Smb2OplockBreakNotification.ReadFrom(_GetResponsePayloadBytes(responseEntry));
            OpenCifsClientOplockBreakNotificationResult oplockBreakResult =
                session.ApplyOplockBreakNotification(
                    responseEntry.Header.TreeId,
                    notification);
            OpenState openState = oplockBreakResult.OpenState;
            Smb2OplockLevel previousOplockLevel = oplockBreakResult.PreviousOplockLevel;
            Smb2OplockLevel newOplockLevel = oplockBreakResult.NewOplockLevel;
            bool requiresAcknowledgment = oplockBreakResult.RequiresAcknowledgment;
            OpenCifsClientOpenHandle openHandle = GetTrackedOpenHandle(openState.PersistentFileId, openState.VolatileFileId);
            openHandle.SetOplockLevel(newOplockLevel);
            bool wasAcknowledged = false;

            if (requiresAcknowledgment)
            {
                Smb2OplockBreakAcknowledgment acknowledgment = session.CreateOplockBreakAcknowledgmentRequest(
                    openState.PersistentFileId,
                    openState.VolatileFileId,
                    newOplockLevel);
                Smb2Header acknowledgmentHeader = session.CreateRequestHeader(Smb2Command.OplockBreak, openHandle.TreeId, sessionId: session.SessionId!.Value);
                OpenCifsClientRequestResponse ackResponseEnvelope = await _SendSingleRequestAsync(
                    acknowledgmentHeader,
                    acknowledgment.ToByteArray(),
                    cancellationToken).ConfigureAwait(false);
                session.ApplyOplockBreakAcknowledgmentResult(
                    openState.PersistentFileId,
                    openState.VolatileFileId,
                    ackResponseEnvelope.ResponseHeader.Status,
                    Smb2OplockBreakResponse.ReadFrom(ackResponseEnvelope.ResponsePayload));
                openHandle.SetOplockLevel(newOplockLevel);
                wasAcknowledged = true;
            }

            OpenCifsClientOplockBreakNotification result = new OpenCifsClientOplockBreakNotification();
            result.ShareName = openHandle.ShareName;
            result.Path = openHandle.Path;
            result.PersistentFileId = openHandle.PersistentFileId;
            result.VolatileFileId = openHandle.VolatileFileId;
            result.PreviousOplockLevel = previousOplockLevel;
            result.NewOplockLevel = newOplockLevel;
            result.WasAcknowledged = wasAcknowledged;
            return result;
        }

        public async Task<OpenCifsClientLeaseBreakNotification> WaitForLeaseBreakAsync(CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            OpenCifsClientSession session = _GetSession();
            byte[] responseBytes = await _ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
            session.ValidateLeaseBreakNotificationPacket(responsePacket, responseBytes);
            Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];
            Smb2LeaseBreakNotification notification = Smb2LeaseBreakNotification.ReadFrom(_GetResponsePayloadBytes(responseEntry));
            OpenCifsClientLeaseBreakNotificationResult leaseBreakResult =
                session.ApplyLeaseBreakNotification(
                    responseEntry.Header.TreeId,
                    notification);
            OpenState openState = leaseBreakResult.OpenState;
            Smb2LeaseState previousLeaseState = leaseBreakResult.PreviousLeaseState;
            Smb2LeaseState newLeaseState = leaseBreakResult.NewLeaseState;
            bool requiresAcknowledgment = leaseBreakResult.RequiresAcknowledgment;
            OpenCifsClientOpenHandle openHandle = GetTrackedOpenHandle(openState.PersistentFileId, openState.VolatileFileId);
            openHandle.SetLeaseState(newLeaseState);
            bool wasAcknowledged = false;

            if (requiresAcknowledgment)
            {
                Smb2LeaseBreakAcknowledgment acknowledgment = session.CreateLeaseBreakAcknowledgmentRequest(
                    openState.PersistentFileId,
                    openState.VolatileFileId);
                Smb2Header acknowledgmentHeader = session.CreateRequestHeader(Smb2Command.OplockBreak, openHandle.TreeId, sessionId: session.SessionId!.Value);
                OpenCifsClientRequestResponse ackResponseEnvelope = await _SendSingleRequestAsync(
                    acknowledgmentHeader,
                    acknowledgment.ToByteArray(),
                    cancellationToken).ConfigureAwait(false);
                session.ApplyLeaseBreakAcknowledgmentResult(
                    openState.PersistentFileId,
                    openState.VolatileFileId,
                    ackResponseEnvelope.ResponseHeader.Status,
                    Smb2LeaseBreakResponse.ReadFrom(ackResponseEnvelope.ResponsePayload));
                openHandle.SetLeaseState(newLeaseState);
                wasAcknowledged = true;
            }

            OpenCifsClientLeaseBreakNotification result = new OpenCifsClientLeaseBreakNotification();
            result.ShareName = openHandle.ShareName;
            result.Path = openHandle.Path;
            result.PersistentFileId = openHandle.PersistentFileId;
            result.VolatileFileId = openHandle.VolatileFileId;
            result.PreviousLeaseState = previousLeaseState;
            result.NewLeaseState = newLeaseState;
            result.WasAcknowledged = wasAcknowledged;
            return result;
        }

        public void ValidateTreeHandle(OpenCifsClientTreeHandle treeHandle)
        {
            _EnsureAuthenticatedSession();

            if (treeHandle == null)
            {
                throw new ArgumentNullException(nameof(treeHandle), "TreeHandle cannot be null.");
            }

            if (treeHandle.ConnectionId != _ConnectionId || treeHandle.SessionGeneration != _GetSessionGeneration())
            {
                throw new OpenCifsClientStateException("The specified tree handle does not belong to the current client connection lifecycle.");
            }

            if (treeHandle.IsDisconnected)
            {
                throw new OpenCifsClientStateException("The specified tree handle has already been disconnected.");
            }

            if (!_ActiveTreesById.TryGetValue(treeHandle.TreeId, out OpenCifsClientTreeHandle? trackedTreeHandle) || !ReferenceEquals(trackedTreeHandle, treeHandle))
            {
                throw new OpenCifsClientStateException("The specified tree handle is no longer active on this client connection.");
            }
        }

        public void ValidateOpenHandle(OpenCifsClientOpenHandle openHandle)
        {
            _EnsureAuthenticatedSession();

            if (openHandle == null)
            {
                throw new ArgumentNullException(nameof(openHandle), "OpenHandle cannot be null.");
            }

            if (openHandle.ConnectionId != _ConnectionId || openHandle.SessionGeneration != _GetSessionGeneration())
            {
                throw new OpenCifsClientStateException("The specified open handle does not belong to the current client connection lifecycle.");
            }

            if (openHandle.IsClosed)
            {
                throw new OpenCifsClientStateException("The specified open handle has already been closed.");
            }

            ValidateTreeHandle(openHandle.TreeHandle);
            string key = GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId);

            if (!_ActiveOpensByKey.TryGetValue(key, out OpenCifsClientOpenHandle? trackedOpenHandle) || !ReferenceEquals(trackedOpenHandle, openHandle))
            {
                throw new OpenCifsClientStateException("The specified open handle is no longer active on this client connection.");
            }
        }

        public void ValidateFileOpenHandle(OpenCifsClientOpenHandle openHandle, string operationName)
        {
            ValidateOpenHandle(openHandle);

            if (openHandle.IsDirectory)
            {
                throw new OpenCifsClientStateException(operationName + " requires a file open.");
            }
        }

        public void ValidateDirectoryOpenHandle(OpenCifsClientOpenHandle openHandle, string operationName)
        {
            ValidateOpenHandle(openHandle);

            if (!openHandle.IsDirectory)
            {
                throw new OpenCifsClientStateException(operationName + " requires a directory open.");
            }
        }

        public void RemoveOpenHandle(OpenCifsClientOpenHandle openHandle)
        {
            string key = GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId);
            _ActiveOpensByKey.Remove(key);
            openHandle.InvalidateDurableReconnect();
            openHandle.MarkClosed();
        }

        public void MarkTreeDisconnected(OpenCifsClientTreeHandle treeHandle)
        {
            treeHandle.MarkDisconnected();
            _ActiveTreesById.Remove(treeHandle.TreeId);

            List<OpenCifsClientOpenHandle> openHandles = new List<OpenCifsClientOpenHandle>();

            foreach (OpenCifsClientOpenHandle trackedOpenHandle in _ActiveOpensByKey.Values)
            {
                if (trackedOpenHandle.TreeId == treeHandle.TreeId)
                {
                    openHandles.Add(trackedOpenHandle);
                }
            }

            for (int index = 0; index < openHandles.Count; index++)
            {
                RemoveOpenHandle(openHandles[index]);
            }
        }

        public void InvalidateTrackedHandles(bool invalidateDurableReconnect)
        {
            foreach (OpenCifsClientOpenHandle openHandle in _ActiveOpensByKey.Values)
            {
                if (invalidateDurableReconnect)
                {
                    openHandle.InvalidateDurableReconnect();
                }

                openHandle.MarkClosed();
            }

            foreach (OpenCifsClientTreeHandle treeHandle in _ActiveTreesById.Values)
            {
                treeHandle.MarkDisconnected();
            }

            _ActiveOpensByKey.Clear();
            _ActiveTreesById.Clear();
        }

        private async Task<OpenCifsClientRequestResponse> SendOpenExistingCreateAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint desiredAccess,
            Smb2CreateOptions createOptions,
            CancellationToken cancellationToken,
            Smb2OplockLevel requestedOplockLevel,
            bool requestDurableHandle,
            Smb2LeaseState requestedLeaseState,
            byte[]? leaseKey)
        {
            OpenCifsClientSession session = _GetSession();
            Smb2CreateRequest request = session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess: desiredAccess,
                createDisposition: Smb2CreateDisposition.Open,
                createOptions: createOptions,
                requestedOplockLevel: requestedOplockLevel,
                requestDurableHandle: requestDurableHandle,
                requestedLeaseState: requestedLeaseState,
                leaseKey: leaseKey);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            return await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
        }

        private OpenCifsClientOpenHandle CreateOpenHandle(
            OpenCifsClientSession session,
            OpenCifsClientTreeHandle treeHandle,
            string path,
            Smb2Header responseHeader,
            Smb2CreateResponse createResponse,
            Smb2CreateRequest? originatingRequest,
            bool isDirectory,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel)
        {
            OpenState openState = session.ApplyCreateResult(treeHandle.TreeId, path, responseHeader.Status, createResponse, originatingRequest);
            OpenCifsClientOpenHandle openHandle = new OpenCifsClientOpenHandle(
                _ConnectionId,
                _GetSessionGeneration(),
                treeHandle,
                openState.PersistentFileId,
                openState.VolatileFileId,
                openState.Path,
                isDirectory,
                openState.OplockLevel,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                requestedOplockLevel,
                openState.IsDurable,
                openState.UsesDurableHandleV2,
                openState.DurableCreateGuid,
                openState.DurableTimeoutMs,
                openState.IsPersistent,
                openState.LeaseKey,
                openState.LeaseState);
            _ActiveOpensByKey[GetOpenKey(openHandle.PersistentFileId, openHandle.VolatileFileId)] = openHandle;
            return openHandle;
        }

        private OpenCifsClientOpenHandle GetTrackedOpenHandle(ulong persistentFileId, ulong volatileFileId)
        {
            if (!_ActiveOpensByKey.TryGetValue(GetOpenKey(persistentFileId, volatileFileId), out OpenCifsClientOpenHandle? openHandle))
            {
                throw new OpenCifsClientStateException("The unsolicited SMB2 oplock-break notification does not match a tracked client open handle.");
            }

            return openHandle;
        }

        private static string GetOpenKey(ulong persistentFileId, ulong volatileFileId)
        {
            return persistentFileId.ToString(CultureInfo.InvariantCulture) +
                ":" +
                volatileFileId.ToString(CultureInfo.InvariantCulture);
        }

        private readonly IDictionary<uint, OpenCifsClientTreeHandle> _ActiveTreesById;
        private readonly IDictionary<string, OpenCifsClientOpenHandle> _ActiveOpensByKey;
        private readonly Guid _ConnectionId;
        private readonly Func<long> _GetSessionGeneration;
        private readonly Func<OpenCifsClientSession> _GetSession;
        private readonly Action _EnsureAuthenticatedSession;
        private readonly Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> _SendSingleRequestAsync;
        private readonly Func<CancellationToken, Task<byte[]>> _ReadNextResponsePacketBytesAsync;
        private readonly Func<Smb2CompoundPacketEntry, byte[]> _GetResponsePayloadBytes;
    }
}
