namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientSessionTreeAndOpenService
    {
        public OpenCifsClientSessionTreeAndOpenService(
            OpenCifsClientOptions options,
            IDictionary<uint, TreeConnectState> trees,
            IDictionary<ulong, ClientOpenRecord> opens,
            Func<bool> getIsAuthenticated,
            Func<ulong?> getSessionId,
            Func<SmbDialect?> getNegotiatedDialect,
            Action<uint> ensureConnectedTree,
            Func<ulong, ulong, ClientOpenRecord> getTrackedOpen,
            Func<uint, byte[], ClientOpenRecord> getTrackedOpenByLeaseKey,
            Func<string, string> normalizeOpenPath,
            Action<uint> removeOpensForTree)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _Trees = trees ?? throw new ArgumentNullException(nameof(trees), "Trees cannot be null.");
            _Opens = opens ?? throw new ArgumentNullException(nameof(opens), "Opens cannot be null.");
            _GetIsAuthenticated = getIsAuthenticated ?? throw new ArgumentNullException(nameof(getIsAuthenticated), "GetIsAuthenticated cannot be null.");
            _GetSessionId = getSessionId ?? throw new ArgumentNullException(nameof(getSessionId), "GetSessionId cannot be null.");
            _GetNegotiatedDialect = getNegotiatedDialect ?? throw new ArgumentNullException(nameof(getNegotiatedDialect), "GetNegotiatedDialect cannot be null.");
            _EnsureConnectedTree = ensureConnectedTree ?? throw new ArgumentNullException(nameof(ensureConnectedTree), "EnsureConnectedTree cannot be null.");
            _GetTrackedOpen = getTrackedOpen ?? throw new ArgumentNullException(nameof(getTrackedOpen), "GetTrackedOpen cannot be null.");
            _GetTrackedOpenByLeaseKey = getTrackedOpenByLeaseKey ?? throw new ArgumentNullException(nameof(getTrackedOpenByLeaseKey), "GetTrackedOpenByLeaseKey cannot be null.");
            _NormalizeOpenPath = normalizeOpenPath ?? throw new ArgumentNullException(nameof(normalizeOpenPath), "NormalizeOpenPath cannot be null.");
            _RemoveOpensForTree = removeOpensForTree ?? throw new ArgumentNullException(nameof(removeOpensForTree), "RemoveOpensForTree cannot be null.");
        }

        public Smb2TreeConnectRequest CreateTreeConnectRequest(string shareName)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            if (!_GetIsAuthenticated() || !_GetSessionId().HasValue)
            {
                throw new OpenCifsClientStateException("An authenticated session is required before tree connect.");
            }

            Smb2TreeConnectRequest request = new Smb2TreeConnectRequest
            {
                Flags = 0,
                Path = "\\\\" + _Options.ServerName + "\\" + shareName.Trim('\\')
            };

            Smb2TreeConnectRequestValidator.Validate(request);
            return request;
        }

        public void ApplyTreeConnectResult(string shareName, uint treeId, NtStatus status, Smb2TreeConnectResponse response)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.TreeConnect, status);
            }

            if (treeId == 0)
            {
                throw new OpenCifsClientStateException("The server did not assign a valid tree identifier.");
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2TreeConnectResponseValidator.Validate(response);

            TreeConnectState treeState = new TreeConnectState();
            treeState.Connect(treeId, shareName.Trim('\\'), (Smb2ShareFlags)response.ShareFlags);
            _Trees[treeId] = treeState;
        }

        public Smb2CreateRequest CreateCreateRequest(
            uint treeId,
            string path,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel,
            bool requestDurableHandle,
            Smb2LeaseState requestedLeaseState,
            byte[]? leaseKey)
        {
            List<Smb2CreateContext> createContexts = new List<Smb2CreateContext>();

            if (requestDurableHandle)
            {
                if (_GetNegotiatedDialect().HasValue && _GetNegotiatedDialect()!.Value >= SmbDialect.Smb30)
                {
                    createContexts.Add(new Smb2DurableHandleRequestV2Context
                    {
                        Timeout = 0,
                        Flags = Smb2DurableHandleFlags.None,
                        CreateGuid = Guid.NewGuid()
                    }.ToCreateContext());
                }
                else
                {
                    createContexts.Add(Smb2DurableHandleRequestContext.Create());
                }
            }

            if (requestedOplockLevel == Smb2OplockLevel.Lease)
            {
                Smb2LeaseState effectiveLeaseState = requestedLeaseState == Smb2LeaseState.None
                    ? Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                    : requestedLeaseState;
                byte[] effectiveLeaseKey = CreateLeaseKey(leaseKey);
                createContexts.Add(new Smb2CreateRequestLeaseContext
                {
                    LeaseKey = effectiveLeaseKey,
                    LeaseState = effectiveLeaseState
                }.ToCreateContext());
            }

            return CreateCreateRequestCore(
                treeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                requestedOplockLevel,
                createContexts.Count == 0
                    ? Array.Empty<byte>()
                    : Smb2CreateContextCodec.Encode(createContexts));
        }

        public Smb2CreateRequest CreateDurableReconnectCreateRequest(
            uint treeId,
            string path,
            ulong persistentFileId,
            ulong volatileFileId,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel,
            Smb2LeaseState requestedLeaseState,
            byte[]? leaseKey,
            Guid durableCreateGuid,
            bool useDurableHandleV2)
        {
            List<Smb2CreateContext> createContexts = new List<Smb2CreateContext>();

            if (useDurableHandleV2)
            {
                if (durableCreateGuid == Guid.Empty)
                {
                    throw new OpenCifsClientStateException("SMB 3.x durable-handle reconnect v2 requires a non-empty durable create GUID.");
                }

                createContexts.Add(new Smb2DurableHandleReconnectV2Context
                {
                    PersistentFileId = persistentFileId,
                    VolatileFileId = volatileFileId,
                    CreateGuid = durableCreateGuid,
                    Flags = Smb2DurableHandleFlags.None
                }.ToCreateContext());
            }
            else
            {
                createContexts.Add(new Smb2DurableHandleReconnectContext
                {
                    PersistentFileId = persistentFileId,
                    VolatileFileId = volatileFileId
                }.ToCreateContext());
            }

            if (requestedOplockLevel == Smb2OplockLevel.Lease && leaseKey != null)
            {
                createContexts.Add(new Smb2CreateRequestLeaseContext
                {
                    LeaseKey = CreateLeaseKey(leaseKey),
                    LeaseState = requestedLeaseState == Smb2LeaseState.None
                        ? Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching
                        : requestedLeaseState
                }.ToCreateContext());
            }

            return CreateCreateRequestCore(
                treeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions,
                requestedOplockLevel,
                Smb2CreateContextCodec.Encode(createContexts));
        }

        public OpenState ApplyCreateResult(uint treeId, string path, NtStatus status, Smb2CreateResponse response, Smb2CreateRequest? originatingRequest = null)
        {
            _EnsureConnectedTree(treeId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Create, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            try
            {
                Smb2CreateResponseValidator.Validate(response);
            }
            catch (ProtocolValidationException exception)
            {
                throw new OpenCifsClientProtocolException(exception.Message, exception.ParamName, exception);
            }

            string normalizedPath = _NormalizeOpenPath(path);
            bool durableGranted = false;
            bool durableHandleV2Granted = false;
            Guid durableCreateGuid = Guid.Empty;
            uint durableTimeoutMs = 0;
            bool isPersistent = false;
            Smb2CreateResponseLeaseContext? leaseResponseContext = null;

            Smb2CreateContext[] createContexts = Smb2CreateContextCodec.Decode(response.CreateContexts);

            if (originatingRequest != null)
            {
                Smb2CreateContext[] requestCreateContexts = Smb2CreateContextCodec.Decode(originatingRequest.CreateContexts);

                for (int index = 0; index < requestCreateContexts.Length; index++)
                {
                    if (Smb2DurableHandleRequestV2Context.IsMatch(requestCreateContexts[index]))
                    {
                        durableCreateGuid = Smb2DurableHandleRequestV2Context.ReadFrom(requestCreateContexts[index]).CreateGuid;
                        break;
                    }

                    if (Smb2DurableHandleReconnectV2Context.IsMatch(requestCreateContexts[index]))
                    {
                        durableCreateGuid = Smb2DurableHandleReconnectV2Context.ReadFrom(requestCreateContexts[index]).CreateGuid;
                        break;
                    }
                }
            }

            for (int index = 0; index < createContexts.Length; index++)
            {
                if (Smb2DurableHandleResponseContext.IsMatch(createContexts[index]))
                {
                    durableGranted = true;
                    continue;
                }

                if (Smb2DurableHandleResponseV2Context.IsMatch(createContexts[index]))
                {
                    Smb2DurableHandleResponseV2Context durableResponseV2 = Smb2DurableHandleResponseV2Context.ReadFrom(createContexts[index]);
                    durableGranted = true;
                    durableHandleV2Granted = true;
                    durableTimeoutMs = durableResponseV2.Timeout;
                    isPersistent = (durableResponseV2.Flags & Smb2DurableHandleFlags.Persistent) != 0;
                    continue;
                }

                if (Smb2CreateResponseLeaseContext.IsMatch(createContexts[index]))
                {
                    leaseResponseContext = Smb2CreateResponseLeaseContext.ReadFrom(createContexts[index]);
                }
            }

            OpenState openState = new OpenState();
            openState.Bind(response.PersistentFileId, response.VolatileFileId, normalizedPath);
            openState.SetOplockLevel(response.OplockLevel);
            openState.SetDurable(durableGranted, durableHandleV2Granted, durableCreateGuid, durableTimeoutMs, isPersistent);

            if (leaseResponseContext != null)
            {
                openState.SetLease(leaseResponseContext.LeaseKey, leaseResponseContext.LeaseState);
            }

            if (_Opens.TryGetValue(response.VolatileFileId, out ClientOpenRecord? existingRecord))
            {
                existingRecord.State.Dispose();
            }

            _Opens[response.VolatileFileId] = new ClientOpenRecord
            {
                TreeId = treeId,
                State = openState
            };

            return openState;
        }

        public Smb2LeaseBreakAcknowledgment CreateLeaseBreakAcknowledgmentRequest(ulong persistentFileId, ulong volatileFileId)
        {
            ClientOpenRecord openRecord = _GetTrackedOpen(persistentFileId, volatileFileId);

            if (openRecord.State.LeaseKey.Length != 16)
            {
                throw new OpenCifsClientStateException("The specified file identifier is not tracked as an SMB 2.1 lease-backed open.");
            }

            Smb2LeaseBreakAcknowledgment acknowledgment = new Smb2LeaseBreakAcknowledgment
            {
                LeaseKey = (byte[])openRecord.State.LeaseKey.Clone(),
                LeaseState = openRecord.State.LeaseState
            };
            Smb2LeaseBreakAcknowledgmentValidator.Validate(acknowledgment);
            return acknowledgment;
        }

        public Smb2OplockBreakAcknowledgment CreateOplockBreakAcknowledgmentRequest(ulong persistentFileId, ulong volatileFileId, Smb2OplockLevel oplockLevel)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2OplockBreakAcknowledgment acknowledgment = new Smb2OplockBreakAcknowledgment
            {
                OplockLevel = oplockLevel,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId
            };
            Smb2OplockBreakAcknowledgmentValidator.Validate(acknowledgment);
            return acknowledgment;
        }

        public OpenCifsClientOplockBreakNotificationResult ApplyOplockBreakNotification(
            uint treeId,
            Smb2OplockBreakNotification notification)
        {
            if (notification == null)
            {
                throw new ArgumentNullException(nameof(notification), "Notification cannot be null.");
            }

            Smb2OplockBreakNotificationValidator.Validate(notification);
            ClientOpenRecord openRecord = _GetTrackedOpen(notification.PersistentFileId, notification.VolatileFileId);

            if (treeId != 0 && openRecord.TreeId != treeId)
            {
                throw new OpenCifsClientProtocolException("The SMB2 oplock-break notification tree identifier does not match the tracked open.", nameof(treeId));
            }

            Smb2OplockLevel previousOplockLevel = openRecord.State.OplockLevel;
            bool requiresAcknowledgment;

            if (previousOplockLevel == Smb2OplockLevel.Exclusive &&
                (notification.OplockLevel == Smb2OplockLevel.None || notification.OplockLevel == Smb2OplockLevel.LevelII))
            {
                requiresAcknowledgment = true;
            }
            else if (previousOplockLevel == Smb2OplockLevel.LevelII &&
                     notification.OplockLevel == Smb2OplockLevel.None)
            {
                requiresAcknowledgment = false;
            }
            else
            {
                throw new OpenCifsClientStateException("The unsolicited SMB2 oplock-break notification does not match the tracked client oplock state.");
            }

            openRecord.State.SetOplockLevel(notification.OplockLevel);
            return new OpenCifsClientOplockBreakNotificationResult(
                openRecord.State,
                previousOplockLevel,
                notification.OplockLevel,
                requiresAcknowledgment);
        }

        public OpenCifsClientLeaseBreakNotificationResult ApplyLeaseBreakNotification(
            uint treeId,
            Smb2LeaseBreakNotification notification)
        {
            if (notification == null)
            {
                throw new ArgumentNullException(nameof(notification), "Notification cannot be null.");
            }

            Smb2LeaseBreakNotificationValidator.Validate(notification);
            ClientOpenRecord openRecord = _GetTrackedOpenByLeaseKey(treeId, notification.LeaseKey);
            Smb2LeaseState previousLeaseState = openRecord.State.LeaseState;

            if (previousLeaseState != notification.CurrentLeaseState)
            {
                throw new OpenCifsClientProtocolException("The SMB2 lease-break notification current lease state does not match the tracked open.", nameof(notification));
            }

            if ((notification.NewLeaseState & ~previousLeaseState) != 0)
            {
                throw new OpenCifsClientProtocolException("The SMB2 lease-break notification new lease state is not a subset of the tracked open state.", nameof(notification));
            }

            openRecord.State.SetLeaseState(notification.NewLeaseState);
            return new OpenCifsClientLeaseBreakNotificationResult(
                openRecord.State,
                previousLeaseState,
                notification.NewLeaseState,
                (notification.Flags & Smb2LeaseBreakNotificationFlags.AcknowledgmentRequired) != 0);
        }

        public void ApplyOplockBreakAcknowledgmentResult(
            ulong persistentFileId,
            ulong volatileFileId,
            NtStatus status,
            Smb2OplockBreakResponse response)
        {
            ClientOpenRecord openRecord = _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.OplockBreak, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2OplockBreakResponseValidator.Validate(response);
            openRecord.State.SetOplockLevel(response.OplockLevel);
        }

        public void ApplyLeaseBreakAcknowledgmentResult(
            ulong persistentFileId,
            ulong volatileFileId,
            NtStatus status,
            Smb2LeaseBreakResponse response)
        {
            ClientOpenRecord openRecord = _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.OplockBreak, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2LeaseBreakResponseValidator.Validate(response);

            if (!response.LeaseKey.AsSpan().SequenceEqual(openRecord.State.LeaseKey))
            {
                throw new OpenCifsClientProtocolException("The SMB2 lease-break response lease key does not match the tracked open.", nameof(response));
            }

            openRecord.State.SetLeaseState(response.LeaseState);
        }

        public Smb2TreeDisconnectRequest CreateTreeDisconnectRequest(uint treeId)
        {
            if (!_Trees.ContainsKey(treeId))
            {
                throw new OpenCifsClientStateException("The specified tree identifier is not connected on this client session.");
            }

            Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest();
            Smb2TreeDisconnectRequestValidator.Validate(request);
            return request;
        }

        public void ApplyTreeDisconnectResult(uint treeId, NtStatus status, Smb2TreeDisconnectResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.TreeDisconnect, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2TreeDisconnectResponseValidator.Validate(response);
            _RemoveOpensForTree(treeId);

            if (_Trees.TryGetValue(treeId, out TreeConnectState? treeState))
            {
                treeState.Disconnect();
                treeState.Dispose();
                _Trees.Remove(treeId);
            }
        }

        private Smb2CreateRequest CreateCreateRequestCore(
            uint treeId,
            string path,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            Smb2OplockLevel requestedOplockLevel,
            byte[] createContexts)
        {
            _EnsureConnectedTree(treeId);
            string normalizedPath = _NormalizeOpenPath(path);

            Smb2CreateRequest request = new Smb2CreateRequest
            {
                RequestedOplockLevel = requestedOplockLevel,
                ImpersonationLevel = Smb2ImpersonationLevel.Impersonation,
                DesiredAccess = desiredAccess,
                FileAttributes = fileAttributes,
                ShareAccess = shareAccess,
                CreateDisposition = createDisposition,
                CreateOptions = createOptions,
                Name = normalizedPath,
                CreateContexts = createContexts ?? Array.Empty<byte>()
            };

            try
            {
                Smb2CreateRequestValidator.Validate(request);
            }
            catch (ProtocolValidationException exception)
            {
                throw new OpenCifsClientProtocolException(exception.Message, exception.ParamName, exception);
            }

            return request;
        }

        private static byte[] CreateLeaseKey(byte[]? leaseKey)
        {
            if (leaseKey == null)
            {
                return RandomNumberGenerator.GetBytes(16);
            }

            if (leaseKey.Length != 16)
            {
                throw new ArgumentException("The SMB 2.1 lease key must be 16 bytes long.", nameof(leaseKey));
            }

            return (byte[])leaseKey.Clone();
        }

        private readonly OpenCifsClientOptions _Options;
        private readonly IDictionary<uint, TreeConnectState> _Trees;
        private readonly IDictionary<ulong, ClientOpenRecord> _Opens;
        private readonly Func<bool> _GetIsAuthenticated;
        private readonly Func<ulong?> _GetSessionId;
        private readonly Func<SmbDialect?> _GetNegotiatedDialect;
        private readonly Action<uint> _EnsureConnectedTree;
        private readonly Func<ulong, ulong, ClientOpenRecord> _GetTrackedOpen;
        private readonly Func<uint, byte[], ClientOpenRecord> _GetTrackedOpenByLeaseKey;
        private readonly Func<string, string> _NormalizeOpenPath;
        private readonly Action<uint> _RemoveOpensForTree;
    }
}
