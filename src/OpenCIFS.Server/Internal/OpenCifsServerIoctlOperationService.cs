namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerIoctlOperationService
    {
        private const ulong WildcardFileId = UInt64.MaxValue;

        private readonly OpenCifsServerDfsReferralResolver _DfsReferralResolver;
        private readonly OpenCifsServerNamedPipeOperationService _NamedPipeOperationService;

        public OpenCifsServerIoctlOperationService(
            OpenCifsServerDfsReferralResolver dfsReferralResolver,
            OpenCifsServerNamedPipeOperationService namedPipeOperationService)
        {
            _DfsReferralResolver = dfsReferralResolver ?? throw new ArgumentNullException(nameof(dfsReferralResolver), "DfsReferralResolver cannot be null.");
            _NamedPipeOperationService = namedPipeOperationService ?? throw new ArgumentNullException(nameof(namedPipeOperationService), "NamedPipeOperationService cannot be null.");
        }

        public static Smb2IoctlResponse CreateResponse(Smb2IoctlRequest request)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            return CreateResponse(request.CtlCode, request.PersistentFileId, request.VolatileFileId, Array.Empty<byte>());
        }

        public static Smb2IoctlResponse CreateResponse(uint ctlCode, ulong persistentFileId, ulong volatileFileId, byte[] outputBuffer)
        {
            Smb2IoctlResponse response = new Smb2IoctlResponse
            {
                CtlCode = ctlCode,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                InputBuffer = Array.Empty<byte>(),
                OutputBuffer = outputBuffer ?? Array.Empty<byte>(),
                Flags = 0
            };

            Smb2IoctlResponseValidator.Validate(response);
            return response;
        }

        public static bool IsConnectionScopedFsctl(uint ctlCode)
        {
            switch ((FsctlCode)ctlCode)
            {
                case FsctlCode.DfsGetReferrals:
                case FsctlCode.DfsGetReferralsEx:
                case FsctlCode.QueryNetworkInterfaceInfo:
                case FsctlCode.ValidateNegotiateInfo:
                case FsctlCode.PipeWait:
                    return true;
                default:
                    return false;
            }
        }

        public static bool IsWildcardFileId(ulong persistentFileId, ulong volatileFileId)
        {
            return persistentFileId == WildcardFileId && volatileFileId == WildcardFileId;
        }

        public OpenCifsServerOperationResult<Smb2IoctlResponse> Execute(OpenCifsServerIoctlOperationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }

            switch ((FsctlCode)context.Request.CtlCode)
            {
                case FsctlCode.DfsGetReferrals:
                    return ExecuteDfsGetReferrals(context.Request);
                case FsctlCode.DfsGetReferralsEx:
                    return ExecuteDfsGetReferralsEx(context.Request, context.NegotiatedDialect);
                case FsctlCode.ValidateNegotiateInfo:
                    return ExecuteValidateNegotiateInfo(context);
                case FsctlCode.SrvEnumerateSnapshots:
                    return ExecuteEnumerateSnapshots(context.Request, context.OpenRecord);
                case FsctlCode.PipeTransceive:
                    return _NamedPipeOperationService.ExecutePipeTransceiveIoctl(new OpenCifsServerNamedPipeIoctlOperationContext
                    {
                        SessionRecord = context.SessionRecord,
                        TreeId = context.TreeId,
                        Request = context.Request,
                        OpenRecord = context.OpenRecord,
                        NegotiatedDialect = context.NegotiatedDialect,
                        ServerName = context.ServerName,
                        AvailableShares = context.AvailableShares
                    });
                default:
                    return CreateIoctlResult(NtStatus.NotSupported, CreateResponse(context.Request));
            }
        }

        private static OpenCifsServerOperationResult<Smb2IoctlResponse> ExecuteEnumerateSnapshots(Smb2IoctlRequest request, ServerOpenRecord? openRecord)
        {
            if (request.InputBuffer.Length != 0 || request.MaxInputResponse != 0)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, CreateResponse(request));
            }

            if (request.MaxOutputResponse < 16)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, CreateResponse(request));
            }

            if (openRecord == null)
            {
                return CreateIoctlResult(NtStatus.FileClosed, CreateResponse(request));
            }

            SrvSnapshotArray snapshotArray = new SrvSnapshotArray
            {
                NumberOfSnapshots = 0,
                Snapshots = Array.Empty<string>()
            };

            Smb2IoctlResponse response = CreateResponse(
                request.CtlCode,
                openRecord.State.PersistentFileId,
                openRecord.State.VolatileFileId,
                snapshotArray.ToByteArray());
            return CreateIoctlResult(NtStatus.Success, response);
        }

        private OpenCifsServerOperationResult<Smb2IoctlResponse> ExecuteValidateNegotiateInfo(OpenCifsServerIoctlOperationContext context)
        {
            Smb2IoctlResponse defaultResponse = CreateResponse(context.Request);

            if (context.NegotiatedDialect == null)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (context.Request.MaxOutputResponse < 24)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            ValidateNegotiateInfoRequest validateRequest;

            try
            {
                validateRequest = ValidateNegotiateInfoRequest.ReadFrom(context.Request.InputBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (validateRequest.ClientGuid != context.NegotiatedClientGuid ||
                validateRequest.SecurityMode != context.NegotiatedClientSecurityMode ||
                validateRequest.Capabilities != context.NegotiatedClientCapabilities ||
                !HasEquivalentValidateDialects(validateRequest.Dialects, context.NegotiatedClientDialects))
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            ValidateNegotiateInfoResponse validateResponse = new ValidateNegotiateInfoResponse
            {
                Capabilities = context.NegotiatedServerCapabilities,
                ServerGuid = context.ServerGuid,
                SecurityMode = context.NegotiatedServerSecurityMode,
                Dialect = context.NegotiatedDialect.Value
            };

            Smb2IoctlResponse response = CreateResponse(
                context.Request.CtlCode,
                WildcardFileId,
                WildcardFileId,
                validateResponse.ToByteArray());
            return CreateIoctlResult(NtStatus.Success, response);
        }

        private OpenCifsServerOperationResult<Smb2IoctlResponse> ExecuteDfsGetReferrals(Smb2IoctlRequest request)
        {
            Smb2IoctlResponse defaultResponse = CreateResponse(request);

            if (!_DfsReferralResolver.HasReferrals())
            {
                return CreateIoctlResult(NtStatus.FsDriverRequired, defaultResponse);
            }

            DfsReferralRequest referralRequest;

            try
            {
                referralRequest = DfsReferralRequest.ReadFrom(request.InputBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (referralRequest.MaxReferralLevel < 2)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            NtStatus referralStatus = TryCreateDfsReferralResponse(referralRequest.RequestPath, useVersion3Entries: false, requestedSiteName: string.Empty, out DfsReferralResponse? referralResponse);

            if (referralStatus != NtStatus.Success || referralResponse == null)
            {
                return CreateIoctlResult(referralStatus, defaultResponse);
            }

            byte[] outputBuffer = referralResponse.ToByteArray();
            NtStatus status = NtStatus.Success;

            if (outputBuffer.Length > request.MaxOutputResponse && request.MaxOutputResponse != 0)
            {
                status = NtStatus.BufferOverflow;
                byte[] truncatedBuffer = new byte[request.MaxOutputResponse];
                Array.Copy(outputBuffer, truncatedBuffer, truncatedBuffer.Length);
                outputBuffer = truncatedBuffer;
            }

            Smb2IoctlResponse response = CreateResponse(
                request.CtlCode,
                WildcardFileId,
                WildcardFileId,
                outputBuffer);
            return CreateIoctlResult(status, response);
        }

        private OpenCifsServerOperationResult<Smb2IoctlResponse> ExecuteDfsGetReferralsEx(Smb2IoctlRequest request, SmbDialect? negotiatedDialect)
        {
            Smb2IoctlResponse defaultResponse = CreateResponse(request);

            if (!_DfsReferralResolver.HasReferrals())
            {
                return CreateIoctlResult(NtStatus.FsDriverRequired, defaultResponse);
            }

            if (!negotiatedDialect.HasValue || negotiatedDialect.Value < SmbDialect.Smb30)
            {
                return CreateIoctlResult(NtStatus.NotSupported, defaultResponse);
            }

            DfsReferralRequestEx referralRequest;

            try
            {
                referralRequest = DfsReferralRequestEx.ReadFrom(request.InputBuffer);
            }
            catch (ProtocolEncodingException)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            if (referralRequest.MaxReferralLevel < 2)
            {
                return CreateIoctlResult(NtStatus.InvalidParameter, defaultResponse);
            }

            NtStatus referralStatus = TryCreateDfsReferralResponse(referralRequest.RequestFileName, useVersion3Entries: true, requestedSiteName: referralRequest.SiteName, out DfsReferralResponse? referralResponse);

            if (referralStatus != NtStatus.Success || referralResponse == null)
            {
                return CreateIoctlResult(referralStatus, defaultResponse);
            }

            byte[] outputBuffer = referralResponse.ToByteArray();
            NtStatus status = NtStatus.Success;

            if (outputBuffer.Length > request.MaxOutputResponse && request.MaxOutputResponse != 0)
            {
                status = NtStatus.BufferOverflow;
                byte[] truncatedBuffer = new byte[request.MaxOutputResponse];
                Array.Copy(outputBuffer, truncatedBuffer, truncatedBuffer.Length);
                outputBuffer = truncatedBuffer;
            }

            Smb2IoctlResponse response = CreateResponse(
                request.CtlCode,
                WildcardFileId,
                WildcardFileId,
                outputBuffer);
            return CreateIoctlResult(status, response);
        }

        private NtStatus TryCreateDfsReferralResponse(string requestPath, bool useVersion3Entries, string requestedSiteName, out DfsReferralResponse? response)
        {
            response = null;

            if (!_DfsReferralResolver.TryMatchReferralByRequestPath(requestPath, out DfsReferralMatch? match) || match == null)
            {
                return NtStatus.ObjectPathNotFound;
            }

            OpenCifsServerDfsReferral[] referrals = GetOrderedReferrals(match.Referrals, useVersion3Entries, requestedSiteName);
            string matchedDfsPath = OpenCifsServerDfsReferralResolver.BuildRequestPath(match.ServerName, match.ShareName, match.NamespacePath);

            if (!useVersion3Entries && ContainsNameListReferral(referrals))
            {
                return NtStatus.NotSupported;
            }

            if (useVersion3Entries)
            {
                DfsReferralEntryV3[] entries = new DfsReferralEntryV3[referrals.Length];

                for (int index = 0; index < referrals.Length; index++)
                {
                    OpenCifsServerDfsReferral referral = referrals[index];
                    entries[index] = CreateVersion3ReferralEntry(referral, matchedDfsPath);
                }

                response = new DfsReferralResponse
                {
                    PathConsumed = checked((ushort)(matchedDfsPath.Length * 2)),
                    HeaderFlags = CreateReferralHeaderFlags(referrals)
                };

                for (int index = 0; index < entries.Length; index++)
                {
                    response.EntriesV3.Add(entries[index]);
                }

                return NtStatus.Success;
            }

            DfsReferralEntryV2[] legacyEntries = new DfsReferralEntryV2[referrals.Length];

            for (int index = 0; index < referrals.Length; index++)
            {
                OpenCifsServerDfsReferral referral = referrals[index];
                string targetPath = OpenCifsServerDfsReferralResolver.NormalizeRelativePath(referral.TargetPath);
                string networkAddress = OpenCifsServerDfsReferralResolver.BuildRequestPath(referral.TargetServerName, referral.TargetShareName, targetPath);
                legacyEntries[index] = new DfsReferralEntryV2
                {
                    IsRootTarget = false,
                    TimeToLive = referral.TimeToLiveSeconds,
                    DfsPath = matchedDfsPath,
                    DfsAlternatePath = matchedDfsPath,
                    NetworkAddress = networkAddress
                };
            }

            response = new DfsReferralResponse
            {
                PathConsumed = checked((ushort)(matchedDfsPath.Length * 2)),
                HeaderFlags = DfsReferralHeaderFlags.StorageServers,
                Entries = legacyEntries
            };
            return NtStatus.Success;
        }

        private static bool ContainsNameListReferral(OpenCifsServerDfsReferral[] referrals)
        {
            for (int index = 0; index < referrals.Length; index++)
            {
                if (referrals[index].IsNameListReferral)
                {
                    return true;
                }
            }

            return false;
        }

        private static OpenCifsServerDfsReferral[] GetOrderedReferrals(OpenCifsServerDfsReferral[] referrals, bool useVersion3Entries, string requestedSiteName)
        {
            if (!useVersion3Entries || string.IsNullOrWhiteSpace(requestedSiteName) || referrals.Length <= 1)
            {
                return referrals;
            }

            List<OpenCifsServerDfsReferral> matchingSiteReferrals = new List<OpenCifsServerDfsReferral>();
            List<OpenCifsServerDfsReferral> remainingReferrals = new List<OpenCifsServerDfsReferral>();

            for (int index = 0; index < referrals.Length; index++)
            {
                OpenCifsServerDfsReferral referral = referrals[index];

                if (!referral.IsNameListReferral &&
                    StringComparer.OrdinalIgnoreCase.Equals(referral.SiteName, requestedSiteName))
                {
                    matchingSiteReferrals.Add(referral);
                }
                else
                {
                    remainingReferrals.Add(referral);
                }
            }

            if (matchingSiteReferrals.Count == 0)
            {
                return referrals;
            }

            OpenCifsServerDfsReferral[] orderedReferrals = new OpenCifsServerDfsReferral[referrals.Length];
            int orderedIndex = 0;

            for (int index = 0; index < matchingSiteReferrals.Count; index++)
            {
                orderedReferrals[orderedIndex++] = matchingSiteReferrals[index];
            }

            for (int index = 0; index < remainingReferrals.Count; index++)
            {
                orderedReferrals[orderedIndex++] = remainingReferrals[index];
            }

            return orderedReferrals;
        }

        private static DfsReferralHeaderFlags CreateReferralHeaderFlags(OpenCifsServerDfsReferral[] referrals)
        {
            return ContainsNameListReferral(referrals)
                ? DfsReferralHeaderFlags.ReferralServers
                : DfsReferralHeaderFlags.StorageServers;
        }

        private static DfsReferralEntryV3 CreateVersion3ReferralEntry(OpenCifsServerDfsReferral referral, string matchedDfsPath)
        {
            if (referral.IsNameListReferral)
            {
                return new DfsReferralEntryV3
                {
                    VersionNumber = 4,
                    IsRootTarget = false,
                    ReferralEntryFlags = DfsReferralEntryFlags.NameListReferral,
                    TimeToLive = referral.TimeToLiveSeconds,
                    SpecialName = referral.SpecialName,
                    ExpandedNames = CloneExpandedNames(referral.ExpandedNames)
                };
            }

            string targetPath = OpenCifsServerDfsReferralResolver.NormalizeRelativePath(referral.TargetPath);
            string networkAddress = OpenCifsServerDfsReferralResolver.BuildRequestPath(referral.TargetServerName, referral.TargetShareName, targetPath);
            return new DfsReferralEntryV3
            {
                VersionNumber = 4,
                IsRootTarget = false,
                ReferralEntryFlags = DfsReferralEntryFlags.None,
                TimeToLive = referral.TimeToLiveSeconds,
                DfsPath = matchedDfsPath,
                DfsAlternatePath = matchedDfsPath,
                NetworkAddress = networkAddress,
                ServiceSiteGuid = new byte[16]
            };
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

        private static bool HasEquivalentValidateDialects(IReadOnlyList<SmbDialect> requestDialects, IReadOnlyList<SmbDialect> negotiatedClientDialects)
        {
            if (negotiatedClientDialects.Count == 0)
            {
                return false;
            }

            if (requestDialects.Count != negotiatedClientDialects.Count)
            {
                return false;
            }

            for (int index = 0; index < requestDialects.Count; index++)
            {
                if (requestDialects[index] != negotiatedClientDialects[index])
                {
                    return false;
                }
            }

            return true;
        }

        private static OpenCifsServerOperationResult<Smb2IoctlResponse> CreateIoctlResult(NtStatus status, Smb2IoctlResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2IoctlResponse>
            {
                Status = status,
                Response = response
            };
        }
    }
}
