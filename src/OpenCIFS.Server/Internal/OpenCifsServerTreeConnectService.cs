namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerTreeConnectService
    {
        private readonly Func<uint> _AllocateTreeId;
        private readonly OpenCifsServerOptions _Options;
        private readonly IReadOnlyDictionary<ulong, ServerSessionRecord> _ReadOnlySessions;
        private readonly OpenCifsServerShareRegistryService _ShareRegistryService;
        private readonly Action<string> _WriteDiagnostic;

        public OpenCifsServerTreeConnectService(
            IReadOnlyDictionary<ulong, ServerSessionRecord> sessions,
            OpenCifsServerShareRegistryService shareRegistryService,
            OpenCifsServerOptions options,
            Func<uint> allocateTreeId,
            Action<string> writeDiagnostic)
        {
            _ReadOnlySessions = sessions ?? throw new ArgumentNullException(nameof(sessions), "Sessions cannot be null.");
            _ShareRegistryService = shareRegistryService ?? throw new ArgumentNullException(nameof(shareRegistryService), "ShareRegistryService cannot be null.");
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            _AllocateTreeId = allocateTreeId ?? throw new ArgumentNullException(nameof(allocateTreeId), "AllocateTreeId cannot be null.");
            _WriteDiagnostic = writeDiagnostic ?? throw new ArgumentNullException(nameof(writeDiagnostic), "WriteDiagnostic cannot be null.");
        }

        public OpenCifsServerTreeConnectResult HandleTreeConnect(ulong sessionId, Smb2TreeConnectRequest request)
        {
            Smb2TreeConnectRequestValidator.Validate(request);
            _WriteDiagnostic("Tree connect request received for session " + sessionId + " and path '" + request.Path + "'.");

            if (!_ReadOnlySessions.TryGetValue(sessionId, out ServerSessionRecord? sessionRecord) || !sessionRecord.State.IsAuthenticated)
            {
                _WriteDiagnostic("Tree connect denied because session " + sessionId + " is not authenticated.");
                return new OpenCifsServerTreeConnectResult
                {
                    Status = NtStatus.AccessDenied,
                    TreeId = 0u,
                    Response = new Smb2TreeConnectResponse()
                };
            }

            string shareName = OpenCifsServerDfsReferralResolver.ExtractShareName(request.Path);

            if (!_ShareRegistryService.TryGetEffectiveShare(shareName, out RegisteredShareRecord? shareRecord) || shareRecord == null)
            {
                _WriteDiagnostic("Tree connect could not resolve share '" + shareName + "'.");
                return new OpenCifsServerTreeConnectResult
                {
                    Status = NtStatus.ObjectNameNotFound,
                    TreeId = 0u,
                    Response = new Smb2TreeConnectResponse()
                };
            }

            if (_Options.RequestCallbacks?.TreeConnectCallback != null)
            {
                NtStatus? callbackStatus = _Options.RequestCallbacks.TreeConnectCallback(
                    new OpenCifsServerTreeConnectContext
                    {
                        SessionId = sessionId,
                        ShareName = shareRecord.ShareName,
                        ShareRootPath = shareRecord.RootPath,
                        Request = request
                    });

                if (callbackStatus.HasValue && callbackStatus.Value != NtStatus.Success)
                {
                    _WriteDiagnostic("Tree connect callback rejected share '" + shareRecord.ShareName + "' with status " + callbackStatus.Value.ToString() + ".");
                    return new OpenCifsServerTreeConnectResult
                    {
                        Status = callbackStatus.Value,
                        TreeId = 0u,
                        Response = new Smb2TreeConnectResponse()
                    };
                }
            }

            uint treeId = _AllocateTreeId();
            ServerTreeRecord treeRecord = new ServerTreeRecord
            {
                ShareName = shareRecord.ShareName,
                ShareRootPath = shareRecord.RootPath,
                Backend = shareRecord.Backend,
                IsNamedPipeShare = shareRecord.IsNamedPipeShare
            };
            Smb2ShareFlags shareFlags = _ShareRegistryService.GetShareFlags(shareRecord.ShareName, shareRecord.IsNamedPipeShare);
            treeRecord.State.Connect(treeId, shareRecord.ShareName, shareFlags);
            sessionRecord.Trees[treeId] = treeRecord;

            Smb2TreeConnectResponse response = new Smb2TreeConnectResponse
            {
                ShareType = !shareRecord.IsNamedPipeShare ? Smb2ShareType.Disk : Smb2ShareType.Pipe,
                ShareFlags = (uint)shareFlags,
                Capabilities = 0u,
                MaximalAccess = 2032127u
            };
            Smb2TreeConnectResponseValidator.Validate(response);
            _WriteDiagnostic("Tree connect accepted session " + sessionId + " for share '" + shareRecord.ShareName + "' with tree id " + treeId + ".");

            return new OpenCifsServerTreeConnectResult
            {
                Status = NtStatus.Success,
                TreeId = treeId,
                Response = response
            };
        }
    }
}
