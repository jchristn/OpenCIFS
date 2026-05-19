namespace OpenCIFS.Client
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientAdministrationService
    {
        private const uint DefaultPipeTransceiveOutputLength = 65536;
        private const string SrvsvcPipeName = "srvsvc";

        public OpenCifsClientAdministrationService(
            OpenCifsClientOptions options,
            Func<OpenCifsClientSession> getSession,
            Action ensureAuthenticatedSession,
            Action<OpenCifsClientOpenHandle> validateOpenHandle,
            Func<CancellationToken, Task<OpenCifsClientTreeHandle>> connectIpcTreeAsync,
            Func<OpenCifsClientTreeHandle, string, CancellationToken, Task<OpenCifsClientOpenHandle>> openPipeAsync,
            Func<OpenCifsClientOpenHandle, CancellationToken, Task> closeAsync,
            Func<OpenCifsClientTreeHandle, CancellationToken, Task> disconnectTreeAsync,
            Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> sendSingleRequestAsync)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
            _EnsureAuthenticatedSession = ensureAuthenticatedSession ?? throw new ArgumentNullException(nameof(ensureAuthenticatedSession), "EnsureAuthenticatedSession cannot be null.");
            _ValidateOpenHandle = validateOpenHandle ?? throw new ArgumentNullException(nameof(validateOpenHandle), "ValidateOpenHandle cannot be null.");
            _ConnectIpcTreeAsync = connectIpcTreeAsync ?? throw new ArgumentNullException(nameof(connectIpcTreeAsync), "ConnectIpcTreeAsync cannot be null.");
            _OpenPipeAsync = openPipeAsync ?? throw new ArgumentNullException(nameof(openPipeAsync), "OpenPipeAsync cannot be null.");
            _CloseAsync = closeAsync ?? throw new ArgumentNullException(nameof(closeAsync), "CloseAsync cannot be null.");
            _DisconnectTreeAsync = disconnectTreeAsync ?? throw new ArgumentNullException(nameof(disconnectTreeAsync), "DisconnectTreeAsync cannot be null.");
            _SendSingleRequestAsync = sendSingleRequestAsync ?? throw new ArgumentNullException(nameof(sendSingleRequestAsync), "SendSingleRequestAsync cannot be null.");
        }

        public void ClearCachedReferrals()
        {
            _DfsReferralCache.Clear();
        }

        public async Task<OpenCifsRemoteShareInfo[]> EnumerateRemoteSharesAsync(CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            OpenCifsClientTreeHandle ipcTreeHandle = await _ConnectIpcTreeAsync(cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle? pipeHandle = null;

            try
            {
                pipeHandle = await _OpenPipeAsync(ipcTreeHandle, SrvsvcPipeName, cancellationToken).ConfigureAwait(false);
                await BindSrvsvcAsync(pipeHandle, cancellationToken).ConfigureAwait(false);
                return await EnumerateSrvsvcSharesAsync(pipeHandle, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                await CloseOpenHandleQuietlyAsync(pipeHandle).ConfigureAwait(false);
                await DisconnectTreeQuietlyAsync(ipcTreeHandle).ConfigureAwait(false);
            }
        }

        public async Task<OpenCifsRemoteShareInfo> GetRemoteShareInfoAsync(string shareName, CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            string normalizedShareName = shareName.Trim();
            OpenCifsClientTreeHandle ipcTreeHandle = await _ConnectIpcTreeAsync(cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle? pipeHandle = null;

            try
            {
                pipeHandle = await _OpenPipeAsync(ipcTreeHandle, SrvsvcPipeName, cancellationToken).ConfigureAwait(false);
                await BindSrvsvcAsync(pipeHandle, cancellationToken).ConfigureAwait(false);
                return await GetSrvsvcShareInfoAsync(pipeHandle, normalizedShareName, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                await CloseOpenHandleQuietlyAsync(pipeHandle).ConfigureAwait(false);
                await DisconnectTreeQuietlyAsync(ipcTreeHandle).ConfigureAwait(false);
            }
        }

        public async Task<OpenCifsDfsReferral[]> GetDfsReferralsAsync(string dfsPath, CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            string normalizedDfsPath = NormalizeDfsPath(dfsPath);
            OpenCifsClientSession session = _GetSession();
            bool useDfsGetReferralsEx = ShouldUseDfsGetReferralsEx(session);
            OpenCifsClientTreeHandle ipcTreeHandle = await _ConnectIpcTreeAsync(cancellationToken).ConfigureAwait(false);

            try
            {
                Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Ioctl, ipcTreeHandle.TreeId, sessionId: session.SessionId!.Value);
                Smb2IoctlRequest request = session.CreateConnectionIoctlRequest(
                    (uint)(useDfsGetReferralsEx ? FsctlCode.DfsGetReferralsEx : FsctlCode.DfsGetReferrals),
                    CreateDfsReferralRequestBuffer(normalizedDfsPath, useDfsGetReferralsEx),
                    maxOutputResponse: DefaultPipeTransceiveOutputLength,
                    maxInputResponse: 0,
                    flags: Smb2IoctlFlags.IsFsctl);
                OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
                Smb2Header responseHeader = responseEnvelope.ResponseHeader;
                byte[] responsePayload = responseEnvelope.ResponsePayload;

                if (responseHeader.Status != NtStatus.Success)
                {
                    throw OpenCifsStatusException.CreateFromResponsePayload(Smb2Command.Ioctl, responseHeader.Status, responsePayload);
                }

                Smb2IoctlResponse ioctlResponse = Smb2IoctlResponse.ReadFrom(responsePayload);

                if (ioctlResponse.CtlCode != request.CtlCode)
                {
                    throw new OpenCifsClientProtocolException("The server IOCTL response does not contain the expected DFS referral payload.");
                }

                DfsReferralResponse referralResponse;

                try
                {
                    referralResponse = DfsReferralResponse.ReadFrom(ioctlResponse.OutputBuffer);
                }
                catch (ProtocolEncodingException exception)
                {
                    throw new OpenCifsClientProtocolException("The server DFS referral payload is malformed.", exception);
                }

                OpenCifsDfsReferral[] referrals = ConvertDfsReferralResponse(normalizedDfsPath, referralResponse);
                UpdateDfsReferralCache(referrals);
                return referrals;
            }
            finally
            {
                await DisconnectTreeQuietlyAsync(ipcTreeHandle).ConfigureAwait(false);
            }
        }

        private byte[] CreateDfsReferralRequestBuffer(string normalizedDfsPath, bool useDfsGetReferralsEx)
        {
            if (!useDfsGetReferralsEx)
            {
                return new DfsReferralRequest
                {
                    MaxReferralLevel = 2,
                    RequestPath = normalizedDfsPath
                }.ToByteArray();
            }

            return new DfsReferralRequestEx
            {
                MaxReferralLevel = 4,
                IncludeSiteName = !string.IsNullOrWhiteSpace(_Options.DfsSiteName),
                PathConsumed = 0,
                RequestFileName = normalizedDfsPath,
                SiteName = _Options.DfsSiteName
            }.ToByteArray();
        }

        private static bool ShouldUseDfsGetReferralsEx(OpenCifsClientSession session)
        {
            return session.NegotiatedDialect.HasValue && session.NegotiatedDialect.Value >= SmbDialect.Smb30;
        }

        public async Task<OpenCifsResolvedDfsPath> ResolveDfsPathAsync(string dfsPath, CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();
            string normalizedDfsPath = NormalizeDfsPath(dfsPath);

            if (TryResolveDfsPathFromCache(normalizedDfsPath, out OpenCifsResolvedDfsPath? cachedResolution) && cachedResolution != null)
            {
                return cachedResolution;
            }

            OpenCifsDfsReferral[] referrals = await GetDfsReferralsAsync(normalizedDfsPath, cancellationToken).ConfigureAwait(false);
            return CreateResolvedDfsPath(normalizedDfsPath, referrals, wasResolvedFromCache: false);
        }

        public async Task<byte[]> TransceiveNamedPipeAsync(
            string pipeName,
            byte[] inputBuffer,
            uint maxOutputResponse,
            CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();

            if (inputBuffer == null)
            {
                throw new ArgumentNullException(nameof(inputBuffer), "InputBuffer cannot be null.");
            }

            string normalizedPipeName = NormalizePipeName(pipeName);

            if (maxOutputResponse == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(maxOutputResponse), "MaxOutputResponse must be greater than zero.");
            }

            OpenCifsClientTreeHandle ipcTreeHandle = await _ConnectIpcTreeAsync(cancellationToken).ConfigureAwait(false);
            OpenCifsClientOpenHandle? pipeHandle = null;

            try
            {
                pipeHandle = await _OpenPipeAsync(ipcTreeHandle, normalizedPipeName, cancellationToken).ConfigureAwait(false);
                return await PipeTransceiveAsync(pipeHandle, inputBuffer, maxOutputResponse, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                await CloseOpenHandleQuietlyAsync(pipeHandle).ConfigureAwait(false);
                await DisconnectTreeQuietlyAsync(ipcTreeHandle).ConfigureAwait(false);
            }
        }

        private async Task CloseOpenHandleQuietlyAsync(OpenCifsClientOpenHandle? openHandle)
        {
            if (openHandle == null || openHandle.IsClosed)
            {
                return;
            }

            try
            {
                await _CloseAsync(openHandle, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private async Task DisconnectTreeQuietlyAsync(OpenCifsClientTreeHandle treeHandle)
        {
            if (treeHandle.IsDisconnected)
            {
                return;
            }

            try
            {
                await _DisconnectTreeAsync(treeHandle, CancellationToken.None).ConfigureAwait(false);
            }
            catch
            {
            }
        }

        private async Task BindSrvsvcAsync(OpenCifsClientOpenHandle pipeHandle, CancellationToken cancellationToken)
        {
            DceRpcBindRequest bindRequest = new DceRpcBindRequest
            {
                CallId = GetNextRpcCallId()
            };
            byte[] bindResponseBytes = await PipeTransceiveAsync(
                pipeHandle,
                bindRequest.ToByteArray(),
                maxOutputResponse: 8192,
                cancellationToken).ConfigureAwait(false);
            DceRpcBindAck bindAck = DceRpcBindAck.ReadFrom(bindResponseBytes);
            bindAck.EnsureAccepted();
        }

        private async Task<OpenCifsRemoteShareInfo[]> EnumerateSrvsvcSharesAsync(OpenCifsClientOpenHandle pipeHandle, CancellationToken cancellationToken)
        {
            SrvsvcNetrShareEnumRequest request = new SrvsvcNetrShareEnumRequest();
            DceRpcRequestPdu rpcRequest = new DceRpcRequestPdu
            {
                CallId = GetNextRpcCallId(),
                ContextId = DceRpcConstants.SrvsvcContextId,
                OperationNumber = SrvsvcNetrShareEnumRequest.OperationNumber,
                StubData = request.ToByteArray()
            };

            byte[] rpcResponseBytes = await PipeTransceiveAsync(
                pipeHandle,
                rpcRequest.ToByteArray(),
                maxOutputResponse: DefaultPipeTransceiveOutputLength,
                cancellationToken).ConfigureAwait(false);
            DceRpcResponsePdu rpcResponse = DceRpcResponsePdu.ReadFrom(rpcResponseBytes);
            SrvsvcNetrShareEnumResponse shareResponse = SrvsvcNetrShareEnumResponse.ReadFrom(rpcResponse.StubData);
            OpenCifsRemoteShareInfo[] shares = new OpenCifsRemoteShareInfo[shareResponse.Shares.Length];

            for (int index = 0; index < shareResponse.Shares.Length; index++)
            {
                SrvsvcShareInfo1 share = shareResponse.Shares[index];
                shares[index] = new OpenCifsRemoteShareInfo
                {
                    Name = share.Name,
                    RawType = share.Type,
                    Remark = share.Remark
                };
            }

            return shares;
        }

        private async Task<OpenCifsRemoteShareInfo> GetSrvsvcShareInfoAsync(OpenCifsClientOpenHandle pipeHandle, string shareName, CancellationToken cancellationToken)
        {
            SrvsvcNetrShareGetInfoRequest request = new SrvsvcNetrShareGetInfoRequest
            {
                ShareName = shareName
            };
            DceRpcRequestPdu rpcRequest = new DceRpcRequestPdu
            {
                CallId = GetNextRpcCallId(),
                ContextId = DceRpcConstants.SrvsvcContextId,
                OperationNumber = SrvsvcNetrShareGetInfoRequest.OperationNumber,
                StubData = request.ToByteArray()
            };

            byte[] rpcResponseBytes = await PipeTransceiveAsync(
                pipeHandle,
                rpcRequest.ToByteArray(),
                maxOutputResponse: DefaultPipeTransceiveOutputLength,
                cancellationToken).ConfigureAwait(false);
            DceRpcResponsePdu rpcResponse = DceRpcResponsePdu.ReadFrom(rpcResponseBytes);
            SrvsvcNetrShareGetInfoResponse shareResponse = SrvsvcNetrShareGetInfoResponse.ReadFrom(rpcResponse.StubData);

            if (shareResponse.ReturnCode != SrvsvcNetrShareGetInfoResponse.ErrorSuccess)
            {
                throw new OpenCifsClientRpcException("SRVSVC", "NetrShareGetInfo", shareResponse.ReturnCode);
            }

            SrvsvcShareInfo2 share = shareResponse.Share ?? throw new OpenCifsClientProtocolException("The server SRVSVC share-info response omitted the required share details.");
            return new OpenCifsRemoteShareInfo
            {
                Name = share.Name,
                RawType = share.Type,
                Remark = share.Remark,
                Permissions = share.Permissions,
                MaximumUses = share.MaximumUses,
                CurrentUses = share.CurrentUses,
                LocalPath = share.Path
            };
        }

        private OpenCifsDfsReferral[] ConvertDfsReferralResponse(string requestedPath, DfsReferralResponse response)
        {
            int totalEntries = response.EntriesV2.Count + response.EntriesV3.Count;

            if (totalEntries == 0)
            {
                throw new OpenCifsClientProtocolException("The server DFS referral response did not contain any referral entries.");
            }

            OpenCifsDfsReferral[] referrals = new OpenCifsDfsReferral[totalEntries];
            string fallbackReferralPath = DeriveReferralPathFromConsumed(requestedPath, response.PathConsumed);
            DateTime referralBaseTimeUtc = DateTime.UtcNow;
            int referralIndex = 0;

            for (int index = 0; index < response.EntriesV2.Count; index++)
            {
                DfsReferralEntryV2 entry = response.EntriesV2[index];
                referrals[referralIndex++] = CreateDfsReferral(
                    requestedPath,
                    response.PathConsumed,
                    fallbackReferralPath,
                    entry.IsRootTarget,
                    entry.TimeToLive,
                    entry.DfsPath,
                    entry.NetworkAddress,
                    referralBaseTimeUtc);
            }

            for (int index = 0; index < response.EntriesV3.Count; index++)
            {
                DfsReferralEntryV3 entry = response.EntriesV3[index];

                if ((entry.ReferralEntryFlags & DfsReferralEntryFlags.NameListReferral) != 0)
                {
                    referrals[referralIndex++] = CreateNameListDfsReferral(
                        requestedPath,
                        response.PathConsumed,
                        fallbackReferralPath,
                        entry.IsRootTarget,
                        entry.TimeToLive,
                        entry.SpecialName,
                        entry.ExpandedNames,
                        referralBaseTimeUtc);
                }
                else
                {
                    referrals[referralIndex++] = CreateDfsReferral(
                        requestedPath,
                        response.PathConsumed,
                        fallbackReferralPath,
                        entry.IsRootTarget,
                        entry.TimeToLive,
                        entry.DfsPath,
                        entry.NetworkAddress,
                        referralBaseTimeUtc);
                }
            }

            return referrals;
        }

        private static OpenCifsDfsReferral CreateDfsReferral(
            string requestedPath,
            ushort pathConsumed,
            string fallbackReferralPath,
            bool isRootTarget,
            uint timeToLive,
            string dfsPath,
            string networkAddress,
            DateTime referralBaseTimeUtc)
        {
            ParseDfsNetworkAddress(networkAddress, out string targetServerName, out string targetShareName, out string targetPath);
            DateTime expiresAtUtc = referralBaseTimeUtc.AddSeconds(timeToLive);
            string referralPath = string.IsNullOrWhiteSpace(dfsPath)
                ? fallbackReferralPath
                : NormalizeDfsPath(dfsPath);
            return new OpenCifsDfsReferral
            {
                RequestedPath = requestedPath,
                ReferralPath = referralPath,
                NetworkAddress = networkAddress,
                TargetServerName = targetServerName,
                TargetShareName = targetShareName,
                TargetPath = targetPath,
                PathConsumed = pathConsumed,
                TimeToLiveSeconds = timeToLive,
                ExpiresAtUtc = expiresAtUtc,
                IsRootTarget = isRootTarget
            };
        }

        private static OpenCifsDfsReferral CreateNameListDfsReferral(
            string requestedPath,
            ushort pathConsumed,
            string fallbackReferralPath,
            bool isRootTarget,
            uint timeToLive,
            string specialName,
            string[] expandedNames,
            DateTime referralBaseTimeUtc)
        {
            DateTime expiresAtUtc = referralBaseTimeUtc.AddSeconds(timeToLive);
            OpenCifsDfsReferral referral = new OpenCifsDfsReferral
            {
                RequestedPath = requestedPath,
                ReferralPath = fallbackReferralPath,
                NetworkAddress = string.Empty,
                IsNameListReferral = true,
                SpecialName = specialName ?? string.Empty,
                ExpandedNames = CloneExpandedNames(expandedNames),
                TargetServerName = string.Empty,
                TargetShareName = string.Empty,
                TargetPath = string.Empty,
                PathConsumed = pathConsumed,
                TimeToLiveSeconds = timeToLive,
                ExpiresAtUtc = expiresAtUtc,
                IsRootTarget = isRootTarget
            };
            return referral;
        }

        private OpenCifsResolvedDfsPath CreateResolvedDfsPath(string originalPath, OpenCifsDfsReferral[] referrals, bool wasResolvedFromCache)
        {
            if (referrals == null || referrals.Length == 0)
            {
                throw new OpenCifsClientProtocolException("At least one DFS referral entry is required to resolve a DFS path.");
            }

            OpenCifsDfsReferral[] resolvableReferrals = CollectResolvableDfsReferrals(referrals);

            if (resolvableReferrals.Length == 0)
            {
                throw new OpenCifsClientStateException("The DFS referral response only contained NameList domain or domain-controller entries, which the bounded managed resolver does not convert into a storage target path.");
            }

            OpenCifsDfsReferral referral = SelectPreferredDfsReferral(originalPath, resolvableReferrals);

            if ((referral.PathConsumed & 1) != 0)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count is not a valid Unicode byte count.");
            }

            int consumedCharacterCount = referral.PathConsumed / 2;

            if (consumedCharacterCount < 0 || consumedCharacterCount > originalPath.Length)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count exceeds the original DFS request path.");
            }

            string unresolvedSuffix = originalPath.Substring(consumedCharacterCount).Trim('\\');
            string targetRelativePath = CombineDfsRelativePath(referral.TargetPath, unresolvedSuffix);
            string targetUncPath = BuildTargetUncPath(referral.TargetServerName, referral.TargetShareName, targetRelativePath);
            return new OpenCifsResolvedDfsPath
            {
                OriginalPath = originalPath,
                ReferralPath = referral.ReferralPath,
                TargetServerName = referral.TargetServerName,
                TargetShareName = referral.TargetShareName,
                TargetRelativePath = targetRelativePath,
                TargetUncPath = targetUncPath,
                ExpiresAtUtc = referral.ExpiresAtUtc,
                WasResolvedFromCache = wasResolvedFromCache,
                IsSameServer = StringComparer.OrdinalIgnoreCase.Equals(NormalizeServerName(referral.TargetServerName), NormalizeServerName(_Options.ServerName))
            };
        }

        private bool TryResolveDfsPathFromCache(string normalizedDfsPath, out OpenCifsResolvedDfsPath? resolvedPath)
        {
            PruneExpiredDfsReferralCache();
            resolvedPath = null;
            DfsReferralCacheEntry? bestEntry = null;
            int bestMatchLength = -1;

            foreach (DfsReferralCacheEntry cacheEntry in _DfsReferralCache.Values)
            {
                if (!DoesDfsPrefixMatch(cacheEntry.ReferralPath, normalizedDfsPath))
                {
                    continue;
                }

                if (cacheEntry.ReferralPath.Length > bestMatchLength)
                {
                    bestMatchLength = cacheEntry.ReferralPath.Length;
                    bestEntry = cacheEntry;
                }
            }

            if (bestEntry == null)
            {
                return false;
            }

            bestEntry.LastAccessUtc = DateTime.UtcNow;
            resolvedPath = CreateResolvedDfsPath(normalizedDfsPath, bestEntry.Referrals, wasResolvedFromCache: true);
            return true;
        }

        private void UpdateDfsReferralCache(OpenCifsDfsReferral[] referrals)
        {
            if (referrals == null || referrals.Length == 0)
            {
                return;
            }

            OpenCifsDfsReferral[] resolvableReferrals = CollectResolvableDfsReferrals(referrals);

            if (resolvableReferrals.Length == 0)
            {
                return;
            }

            PruneExpiredDfsReferralCache();
            string referralPath = NormalizeDfsPath(resolvableReferrals[0].ReferralPath);
            DateTime expiresAtUtc = resolvableReferrals[0].ExpiresAtUtc;

            for (int index = 1; index < resolvableReferrals.Length; index++)
            {
                if (resolvableReferrals[index].ExpiresAtUtc < expiresAtUtc)
                {
                    expiresAtUtc = resolvableReferrals[index].ExpiresAtUtc;
                }
            }

            _DfsReferralCache[referralPath] = new DfsReferralCacheEntry
            {
                ReferralPath = referralPath,
                ExpiresAtUtc = expiresAtUtc,
                LastAccessUtc = DateTime.UtcNow,
                Referrals = CloneDfsReferrals(resolvableReferrals)
            };
            EnforceDfsReferralCacheCapacity();
        }

        private void PruneExpiredDfsReferralCache()
        {
            DateTime utcNow = DateTime.UtcNow;
            List<string>? expiredKeys = null;

            foreach (KeyValuePair<string, DfsReferralCacheEntry> cacheEntry in _DfsReferralCache)
            {
                if (cacheEntry.Value.ExpiresAtUtc > utcNow)
                {
                    continue;
                }

                expiredKeys ??= new List<string>();
                expiredKeys.Add(cacheEntry.Key);
            }

            if (expiredKeys == null)
            {
                return;
            }

            for (int index = 0; index < expiredKeys.Count; index++)
            {
                _DfsReferralCache.Remove(expiredKeys[index]);
            }
        }

        private void EnforceDfsReferralCacheCapacity()
        {
            while (_DfsReferralCache.Count > _Options.DfsReferralCacheCapacity)
            {
                string? evictionKey = null;
                DateTime evictionAccessTime = DateTime.MaxValue;
                DateTime evictionExpiryTime = DateTime.MaxValue;

                foreach (KeyValuePair<string, DfsReferralCacheEntry> cacheEntry in _DfsReferralCache)
                {
                    if (evictionKey == null ||
                        cacheEntry.Value.LastAccessUtc < evictionAccessTime ||
                        (cacheEntry.Value.LastAccessUtc == evictionAccessTime && cacheEntry.Value.ExpiresAtUtc < evictionExpiryTime) ||
                        (cacheEntry.Value.LastAccessUtc == evictionAccessTime &&
                         cacheEntry.Value.ExpiresAtUtc == evictionExpiryTime &&
                         StringComparer.OrdinalIgnoreCase.Compare(cacheEntry.Key, evictionKey) < 0))
                    {
                        evictionKey = cacheEntry.Key;
                        evictionAccessTime = cacheEntry.Value.LastAccessUtc;
                        evictionExpiryTime = cacheEntry.Value.ExpiresAtUtc;
                    }
                }

                if (evictionKey == null)
                {
                    return;
                }

                _DfsReferralCache.Remove(evictionKey);
            }
        }

        private async Task<byte[]> PipeTransceiveAsync(
            OpenCifsClientOpenHandle pipeHandle,
            byte[] inputBuffer,
            uint maxOutputResponse,
            CancellationToken cancellationToken)
        {
            if (inputBuffer == null)
            {
                throw new ArgumentNullException(nameof(inputBuffer), "InputBuffer cannot be null.");
            }

            _ValidateOpenHandle(pipeHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2IoctlRequest request = session.CreateIoctlRequest(
                pipeHandle.PersistentFileId,
                pipeHandle.VolatileFileId,
                (uint)FsctlCode.PipeTransceive,
                inputBuffer,
                maxOutputResponse: maxOutputResponse,
                maxInputResponse: 0,
                flags: Smb2IoctlFlags.IsFsctl);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Ioctl, pipeHandle.TreeId, sessionId: session.SessionId!.Value);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;

            if (responseHeader.Status != NtStatus.Success &&
                responseHeader.Status != NtStatus.BufferOverflow)
            {
                throw OpenCifsStatusException.CreateFromResponsePayload(Smb2Command.Ioctl, responseHeader.Status, responsePayload);
            }

            Smb2IoctlResponse response = Smb2IoctlResponse.ReadFrom(responsePayload);

            if (response.CtlCode != (uint)FsctlCode.PipeTransceive)
            {
                throw new OpenCifsClientProtocolException("The server IOCTL response does not contain an FSCTL_PIPE_TRANSCEIVE payload.");
            }

            if (response.PersistentFileId != pipeHandle.PersistentFileId ||
                response.VolatileFileId != pipeHandle.VolatileFileId)
            {
                throw new OpenCifsClientProtocolException("The server IOCTL response file identifier does not match the named-pipe open handle.");
            }

            return response.OutputBuffer;
        }

        private static string NormalizePipeName(string pipeName)
        {
            if (string.IsNullOrWhiteSpace(pipeName))
            {
                throw new ArgumentNullException(nameof(pipeName), "PipeName cannot be null or whitespace.");
            }

            string normalizedPipeName = pipeName.Trim().Replace('/', '\\');

            while (normalizedPipeName.StartsWith("\\", StringComparison.Ordinal))
            {
                normalizedPipeName = normalizedPipeName.Substring(1);
            }

            if (normalizedPipeName.StartsWith("pipe\\", StringComparison.OrdinalIgnoreCase))
            {
                normalizedPipeName = normalizedPipeName.Substring("pipe\\".Length);
            }

            normalizedPipeName = normalizedPipeName.Trim('\\');

            if (normalizedPipeName.Length == 0)
            {
                throw new ArgumentException("PipeName cannot be empty after normalization.", nameof(pipeName));
            }

            return normalizedPipeName;
        }

        private static string NormalizeDfsPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            string normalizedPath = path.Trim().Replace('/', '\\');

            while (normalizedPath.StartsWith("\\\\", StringComparison.Ordinal))
            {
                normalizedPath = normalizedPath.Substring(1);
            }

            normalizedPath = "\\" + normalizedPath.Trim('\\');

            while (normalizedPath.Contains("\\\\", StringComparison.Ordinal))
            {
                normalizedPath = normalizedPath.Replace("\\\\", "\\", StringComparison.Ordinal);
            }

            return normalizedPath;
        }

        private static string DeriveReferralPathFromConsumed(string requestedPath, ushort pathConsumed)
        {
            if ((pathConsumed & 1) != 0)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count is not a valid Unicode byte count.");
            }

            int consumedCharacterCount = pathConsumed / 2;

            if (consumedCharacterCount < 0 || consumedCharacterCount > requestedPath.Length)
            {
                throw new OpenCifsClientProtocolException("The DFS referral path-consumed count exceeds the original DFS request path.");
            }

            return NormalizeDfsPath(requestedPath.Substring(0, consumedCharacterCount));
        }

        private static bool DoesDfsPrefixMatch(string referralPath, string requestedPath)
        {
            if (string.Equals(referralPath, requestedPath, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            return requestedPath.StartsWith(referralPath + "\\", StringComparison.OrdinalIgnoreCase);
        }

        private OpenCifsDfsReferral SelectPreferredDfsReferral(string requestedPath, OpenCifsDfsReferral[] referrals)
        {
            OpenCifsDfsReferral preferredReferral = referrals[0];
            string preferredServerName = NormalizeServerName(_Options.ServerName);
            string preferredShareName = ExtractRequestedShareName(requestedPath);

            for (int index = 1; index < referrals.Length; index++)
            {
                OpenCifsDfsReferral candidateReferral = referrals[index];

                if (IsPreferredDfsReferralCandidate(candidateReferral, preferredReferral, preferredServerName, preferredShareName))
                {
                    preferredReferral = candidateReferral;
                }
            }

            return preferredReferral;
        }

        private static bool IsPreferredDfsReferralCandidate(
            OpenCifsDfsReferral candidateReferral,
            OpenCifsDfsReferral currentReferral,
            string preferredServerName,
            string preferredShareName)
        {
            int candidateScore = GetDfsReferralPreferenceScore(candidateReferral, preferredServerName, preferredShareName);
            int currentScore = GetDfsReferralPreferenceScore(currentReferral, preferredServerName, preferredShareName);

            if (candidateScore != currentScore)
            {
                return candidateScore > currentScore;
            }

            if (candidateReferral.ExpiresAtUtc != currentReferral.ExpiresAtUtc)
            {
                return candidateReferral.ExpiresAtUtc > currentReferral.ExpiresAtUtc;
            }

            return false;
        }

        private static int GetDfsReferralPreferenceScore(
            OpenCifsDfsReferral referral,
            string preferredServerName,
            string preferredShareName)
        {
            bool sameServer = StringComparer.OrdinalIgnoreCase.Equals(
                NormalizeServerName(referral.TargetServerName),
                preferredServerName);
            int score = referral.IsRootTarget ? 0 : 4;

            if (sameServer)
            {
                score += 2;

                if (StringComparer.OrdinalIgnoreCase.Equals(NormalizeShareName(referral.TargetShareName), preferredShareName))
                {
                    score += 1;
                }
            }

            return score;
        }

        private static string ExtractRequestedShareName(string requestedPath)
        {
            string normalizedPath = NormalizeDfsPath(requestedPath);
            string[] parts = normalizedPath.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length < 2
                ? string.Empty
                : NormalizeShareName(parts[1]);
        }

        private static void ParseDfsNetworkAddress(string networkAddress, out string serverName, out string shareName, out string targetPath)
        {
            string normalizedNetworkAddress = NormalizeDfsPath(networkAddress);
            string[] parts = normalizedNetworkAddress.Trim('\\').Split('\\', StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2)
            {
                throw new OpenCifsClientProtocolException("The DFS referral target network address is malformed.");
            }

            serverName = parts[0];
            shareName = parts[1];
            targetPath = parts.Length <= 2 ? string.Empty : string.Join("\\", parts, 2, parts.Length - 2);
        }

        private static string CombineDfsRelativePath(string basePath, string suffix)
        {
            string normalizedBasePath = string.IsNullOrWhiteSpace(basePath) ? string.Empty : basePath.Replace('/', '\\').Trim('\\');
            string normalizedSuffix = string.IsNullOrWhiteSpace(suffix) ? string.Empty : suffix.Replace('/', '\\').Trim('\\');

            if (normalizedBasePath.Length == 0)
            {
                return normalizedSuffix;
            }

            if (normalizedSuffix.Length == 0)
            {
                return normalizedBasePath;
            }

            return normalizedBasePath + "\\" + normalizedSuffix;
        }

        private static string BuildTargetUncPath(string serverName, string shareName, string targetPath)
        {
            string normalizedServerName = NormalizeServerName(serverName);
            string normalizedShareName = shareName.Trim().Trim('\\');
            string normalizedTargetPath = string.IsNullOrWhiteSpace(targetPath) ? string.Empty : targetPath.Replace('/', '\\').Trim('\\');
            return normalizedTargetPath.Length == 0
                ? "\\\\" + normalizedServerName + "\\" + normalizedShareName
                : "\\\\" + normalizedServerName + "\\" + normalizedShareName + "\\" + normalizedTargetPath;
        }

        private static string NormalizeServerName(string serverName)
        {
            if (string.IsNullOrWhiteSpace(serverName))
            {
                return string.Empty;
            }

            return serverName.Trim().Trim('\\');
        }

        private static string NormalizeShareName(string shareName)
        {
            if (string.IsNullOrWhiteSpace(shareName))
            {
                return string.Empty;
            }

            return shareName.Trim().Trim('\\');
        }

        private static bool CanResolveDfsReferralToStorageTarget(OpenCifsDfsReferral referral)
        {
            return referral != null &&
                !referral.IsNameListReferral &&
                !string.IsNullOrWhiteSpace(referral.NetworkAddress) &&
                !string.IsNullOrWhiteSpace(referral.TargetServerName) &&
                !string.IsNullOrWhiteSpace(referral.TargetShareName);
        }

        private static OpenCifsDfsReferral[] CollectResolvableDfsReferrals(OpenCifsDfsReferral[] referrals)
        {
            List<OpenCifsDfsReferral> resolvableReferrals = new List<OpenCifsDfsReferral>();

            for (int index = 0; index < referrals.Length; index++)
            {
                OpenCifsDfsReferral referral = referrals[index];

                if (CanResolveDfsReferralToStorageTarget(referral))
                {
                    resolvableReferrals.Add(referral);
                }
            }

            return resolvableReferrals.ToArray();
        }

        private static string[] CloneExpandedNames(string[] expandedNames)
        {
            if (expandedNames == null)
            {
                return Array.Empty<string>();
            }

            string[] clone = new string[expandedNames.Length];

            for (int index = 0; index < expandedNames.Length; index++)
            {
                clone[index] = expandedNames[index];
            }

            return clone;
        }

        private static OpenCifsDfsReferral[] CloneDfsReferrals(OpenCifsDfsReferral[] referrals)
        {
            OpenCifsDfsReferral[] clones = new OpenCifsDfsReferral[referrals.Length];

            for (int index = 0; index < referrals.Length; index++)
            {
                OpenCifsDfsReferral referral = referrals[index];
                clones[index] = new OpenCifsDfsReferral
                {
                    RequestedPath = referral.RequestedPath,
                    ReferralPath = referral.ReferralPath,
                    NetworkAddress = referral.NetworkAddress,
                    IsNameListReferral = referral.IsNameListReferral,
                    SpecialName = referral.SpecialName,
                    ExpandedNames = CloneExpandedNames(referral.ExpandedNames),
                    TargetServerName = referral.TargetServerName,
                    TargetShareName = referral.TargetShareName,
                    TargetPath = referral.TargetPath,
                    PathConsumed = referral.PathConsumed,
                    TimeToLiveSeconds = referral.TimeToLiveSeconds,
                    ExpiresAtUtc = referral.ExpiresAtUtc,
                    IsRootTarget = referral.IsRootTarget
                };
            }

            return clones;
        }

        private uint GetNextRpcCallId()
        {
            lock (_RpcSyncRoot)
            {
                uint callId = _NextRpcCallId++;
                if (_NextRpcCallId == 0)
                {
                    _NextRpcCallId = 1;
                }

                return callId;
            }
        }

        private readonly OpenCifsClientOptions _Options;
        private readonly Func<OpenCifsClientSession> _GetSession;
        private readonly Action _EnsureAuthenticatedSession;
        private readonly Action<OpenCifsClientOpenHandle> _ValidateOpenHandle;
        private readonly Func<CancellationToken, Task<OpenCifsClientTreeHandle>> _ConnectIpcTreeAsync;
        private readonly Func<OpenCifsClientTreeHandle, string, CancellationToken, Task<OpenCifsClientOpenHandle>> _OpenPipeAsync;
        private readonly Func<OpenCifsClientOpenHandle, CancellationToken, Task> _CloseAsync;
        private readonly Func<OpenCifsClientTreeHandle, CancellationToken, Task> _DisconnectTreeAsync;
        private readonly Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> _SendSingleRequestAsync;
        private readonly Dictionary<string, DfsReferralCacheEntry> _DfsReferralCache = new Dictionary<string, DfsReferralCacheEntry>(StringComparer.OrdinalIgnoreCase);
        private readonly object _RpcSyncRoot = new object();
        private uint _NextRpcCallId = 1;
    }
}
