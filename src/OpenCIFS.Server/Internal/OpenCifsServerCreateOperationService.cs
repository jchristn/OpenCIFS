namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerCreateOperationService
    {
        private readonly Func<Guid> _GetCurrentClientGuid;
        private readonly Func<SmbDialect?> _GetCurrentDialect;
        private readonly OpenCifsServerCreateRequestContextParser _CreateRequestContextParser;
        private readonly OpenCifsServerDurableReconnectCreateOperationService _DurableReconnectCreateOperationService;
        private readonly OpenCifsServerNamedPipeOperationService _NamedPipeOperationService;
        private readonly OpenCifsServerHost _OwnerHost;
        private readonly OpenCifsServerRegularCreateOperationService _RegularCreateOperationService;
        private readonly OpenCifsServerSessionOpenStateService _SessionOpenStateService;
        private readonly OpenCifsServerShareRegistryService _ShareRegistryService;
        private readonly OpenCifsServerOptions _Options;

        public OpenCifsServerCreateOperationService(
            OpenCifsServerHost ownerHost,
            OpenCifsServerOptions options,
            OpenCifsServerSessionOpenStateService sessionOpenStateService,
            OpenCifsServerShareRegistryService shareRegistryService,
            OpenCifsServerCreateRequestContextParser createRequestContextParser,
            OpenCifsServerNamedPipeOperationService namedPipeOperationService,
            OpenCifsServerDurableReconnectCreateOperationService durableReconnectCreateOperationService,
            OpenCifsServerRegularCreateOperationService regularCreateOperationService,
            Func<SmbDialect?> getCurrentDialect,
            Func<Guid> getCurrentClientGuid)
        {
            _OwnerHost = ownerHost ?? throw new ArgumentNullException(nameof(ownerHost), "OwnerHost cannot be null.");
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _SessionOpenStateService = sessionOpenStateService ?? throw new ArgumentNullException(nameof(sessionOpenStateService), "SessionOpenStateService cannot be null.");
            _ShareRegistryService = shareRegistryService ?? throw new ArgumentNullException(nameof(shareRegistryService), "ShareRegistryService cannot be null.");
            _CreateRequestContextParser = createRequestContextParser ?? throw new ArgumentNullException(nameof(createRequestContextParser), "CreateRequestContextParser cannot be null.");
            _NamedPipeOperationService = namedPipeOperationService ?? throw new ArgumentNullException(nameof(namedPipeOperationService), "NamedPipeOperationService cannot be null.");
            _DurableReconnectCreateOperationService = durableReconnectCreateOperationService ?? throw new ArgumentNullException(nameof(durableReconnectCreateOperationService), "DurableReconnectCreateOperationService cannot be null.");
            _RegularCreateOperationService = regularCreateOperationService ?? throw new ArgumentNullException(nameof(regularCreateOperationService), "RegularCreateOperationService cannot be null.");
            _GetCurrentDialect = getCurrentDialect ?? throw new ArgumentNullException(nameof(getCurrentDialect), "GetCurrentDialect cannot be null.");
            _GetCurrentClientGuid = getCurrentClientGuid ?? throw new ArgumentNullException(nameof(getCurrentClientGuid), "GetCurrentClientGuid cannot be null.");
        }

        public OpenCifsServerOperationResult<Smb2CreateResponse> Execute(ulong sessionId, uint treeId, Smb2CreateRequest request)
        {
            Smb2CreateRequestValidator.Validate(request);
            ServerSessionRecord? sessionRecord;
            ServerTreeRecord? treeRecord;

            if (!_SessionOpenStateService.TryGetAuthenticatedTree(sessionId, treeId, out sessionRecord, out treeRecord) ||
                sessionRecord == null ||
                treeRecord == null)
            {
                return CreateOperationResult(NtStatus.AccessDenied, new Smb2CreateResponse());
            }

            ServerSessionRecord authenticatedSessionRecord = sessionRecord;
            ServerTreeRecord authenticatedTreeRecord = treeRecord;

            if (_ShareRegistryService.DfsReferralResolver.TryMatchReferral(authenticatedTreeRecord.ShareName, request.Name, out OpenCifsServerDfsReferral[] _, out string _))
            {
                return CreateOperationResult(NtStatus.PathNotCovered, new Smb2CreateResponse());
            }

            SmbDialect? currentDialect = _GetCurrentDialect();
            OpenCifsServerCreateRequestContextAnalysis? createContextAnalysis;

            if (!_CreateRequestContextParser.TryAnalyze(request, currentDialect, out createContextAnalysis, out NtStatus createContextStatus) ||
                createContextAnalysis == null)
            {
                return CreateOperationResult(createContextStatus, new Smb2CreateResponse());
            }

            OpenCifsServerCreateRequestContextAnalysis analyzedContext = createContextAnalysis;

            if (authenticatedTreeRecord.IsNamedPipeShare)
            {
                return HandleNamedPipeCreate(authenticatedSessionRecord, authenticatedTreeRecord, request, analyzedContext.CreateContexts);
            }

            bool isShareRootOpenRequest = OpenCifsServerPathResolver.IsShareRootOpenRequest(request);

            if (request.Name.Length == 0 && !isShareRootOpenRequest)
            {
                return CreateOperationResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            string? fullPath;

            if (!OpenCifsServerPathResolver.TryResolveShareFilePath(authenticatedTreeRecord.ShareRootPath, request.Name, out fullPath, out NtStatus pathStatus, isShareRootOpenRequest) ||
                fullPath == null)
            {
                return CreateOperationResult(pathStatus, new Smb2CreateResponse());
            }

            string resolvedFullPath = fullPath;
            Guid negotiatedClientGuid = _GetCurrentClientGuid();

            if (analyzedContext.DurableHandleReconnectContext != null)
            {
                return HandleDurableReconnectCreate(
                    authenticatedSessionRecord,
                    authenticatedTreeRecord,
                    request,
                    resolvedFullPath,
                    analyzedContext.DurableHandleReconnectContext.PersistentFileId,
                    null,
                    analyzedContext.LeaseRequestContext,
                    negotiatedClientGuid);
            }

            if (analyzedContext.DurableHandleReconnectV2Context != null)
            {
                return HandleDurableReconnectCreate(
                    authenticatedSessionRecord,
                    authenticatedTreeRecord,
                    request,
                    resolvedFullPath,
                    analyzedContext.DurableHandleReconnectV2Context.PersistentFileId,
                    analyzedContext.DurableHandleReconnectV2Context.CreateGuid,
                    analyzedContext.LeaseRequestContext,
                    negotiatedClientGuid);
            }

            if (_Options.RequestCallbacks?.CreateCallback != null)
            {
                NtStatus? callbackStatus = _Options.RequestCallbacks.CreateCallback(new OpenCifsServerCreateContext
                {
                    SessionId = sessionId,
                    TreeId = treeId,
                    ShareName = authenticatedTreeRecord.ShareName,
                    FullPath = resolvedFullPath,
                    Request = request
                });

                if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
                {
                    return CreateOperationResult(callbackStatus.Value, new Smb2CreateResponse());
                }
            }

            return _RegularCreateOperationService.Execute(new OpenCifsServerRegularCreateOperationContext
            {
                OwnerHost = _OwnerHost,
                SessionId = sessionId,
                TreeId = treeId,
                SessionRecord = authenticatedSessionRecord,
                TreeRecord = authenticatedTreeRecord,
                Request = request,
                FullPath = resolvedFullPath,
                IsShareRootOpenRequest = isShareRootOpenRequest,
                DurableHandleRequested = analyzedContext.DurableHandleRequested,
                DurableHandleRequestV2Context = analyzedContext.DurableHandleRequestV2Context,
                LeaseRequestContext = analyzedContext.LeaseRequestContext,
                NegotiatedDialect = currentDialect,
                NegotiatedClientGuid = negotiatedClientGuid
            });
        }

        private OpenCifsServerOperationResult<Smb2CreateResponse> HandleDurableReconnectCreate(
            ServerSessionRecord sessionRecord,
            ServerTreeRecord treeRecord,
            Smb2CreateRequest request,
            string fullPath,
            ulong persistentFileId,
            Guid? durableCreateGuid,
            Smb2CreateRequestLeaseContext? leaseRequestContext,
            Guid negotiatedClientGuid)
        {
            return _DurableReconnectCreateOperationService.Execute(new OpenCifsServerDurableReconnectCreateOperationContext
            {
                OwnerHost = _OwnerHost,
                SessionRecord = sessionRecord,
                TreeRecord = treeRecord,
                Request = request,
                FullPath = fullPath,
                PersistentFileId = persistentFileId,
                DurableCreateGuid = durableCreateGuid,
                LeaseRequestContext = leaseRequestContext,
                NegotiatedClientGuid = negotiatedClientGuid
            });
        }

        private OpenCifsServerOperationResult<Smb2CreateResponse> HandleNamedPipeCreate(
            ServerSessionRecord sessionRecord,
            ServerTreeRecord treeRecord,
            Smb2CreateRequest request,
            IReadOnlyList<Smb2CreateContext> createContexts)
        {
            return _NamedPipeOperationService.ExecuteCreate(new OpenCifsServerNamedPipeCreateOperationContext
            {
                OwnerHost = _OwnerHost,
                SessionRecord = sessionRecord,
                TreeRecord = treeRecord,
                Request = request,
                CreateContexts = createContexts
            });
        }

        private static OpenCifsServerOperationResult<TResponse> CreateOperationResult<TResponse>(NtStatus status, TResponse response)
            where TResponse : class
        {
            return new OpenCifsServerOperationResult<TResponse>
            {
                Status = status,
                Response = response
            };
        }
    }
}
