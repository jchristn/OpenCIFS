namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerShareRegistryService
    {
        private const string IpcShareName = "IPC$";
        private const string NamedPipePseudoRootPath = "[named-pipes]";

        private readonly Dictionary<string, RegisteredShareRecord> _RegisteredShares = new Dictionary<string, RegisteredShareRecord>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, OpenCifsServerNamedPipeEndpoint> _NamedPipeEndpoints = new Dictionary<string, OpenCifsServerNamedPipeEndpoint>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<OpenCifsServerDfsReferral>> _DfsReferralsByShare = new Dictionary<string, List<OpenCifsServerDfsReferral>>(StringComparer.OrdinalIgnoreCase);
        private readonly OpenCifsServerOptions _Options;

        public OpenCifsServerShareRegistryService(OpenCifsServerOptions options)
        {
            _Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            DfsReferralResolver = new OpenCifsServerDfsReferralResolver(_DfsReferralsByShare);
        }

        public OpenCifsServerDfsReferralResolver DfsReferralResolver { get; }

        public IReadOnlyDictionary<string, OpenCifsServerNamedPipeEndpoint> NamedPipeEndpoints => _NamedPipeEndpoints;

        public void RegisterShare(OpenCifsServerShareBackend share)
        {
            if (share == null)
            {
                throw new ArgumentNullException(nameof(share), "Share cannot be null.");
            }

            RegisteredShareRecord shareRecord = NormalizeRegisteredShare(share);

            if (_RegisteredShares.ContainsKey(shareRecord.ShareName))
            {
                throw new OpenCifsServerConfigurationException("A filesystem-backed share with the same name is already registered.");
            }

            _RegisteredShares.Add(shareRecord.ShareName, shareRecord);
        }

        public void RegisterNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoint endpoint)
        {
            if (endpoint == null)
            {
                throw new ArgumentNullException(nameof(endpoint), "Endpoint cannot be null.");
            }

            if (_NamedPipeEndpoints.ContainsKey(endpoint.PipeName))
            {
                throw new OpenCifsServerConfigurationException("A named-pipe endpoint with the same name is already registered.");
            }

            _NamedPipeEndpoints.Add(endpoint.PipeName, endpoint);
        }

        public void RegisterDfsReferral(OpenCifsServerDfsReferral referral)
        {
            if (referral == null)
            {
                throw new ArgumentNullException(nameof(referral), "Referral cannot be null.");
            }

            OpenCifsServerDfsReferral clonedReferral = referral.Clone();

            if (!_DfsReferralsByShare.TryGetValue(clonedReferral.NamespaceShareName, out List<OpenCifsServerDfsReferral>? referrals) || referrals == null)
            {
                referrals = new List<OpenCifsServerDfsReferral>();
                _DfsReferralsByShare.Add(clonedReferral.NamespaceShareName, referrals);
            }

            if (referrals.Exists(delegate(OpenCifsServerDfsReferral existing) { return existing.IsEquivalentTo(clonedReferral); }))
            {
                throw new OpenCifsServerConfigurationException("An equivalent DFS referral is already registered.");
            }

            referrals.Add(clonedReferral);
        }

        public IReadOnlyList<OpenCifsServerShareInfo> GetAvailableShares()
        {
            bool exposeIpcShare = ShouldExposeIpcShare();

            if (_RegisteredShares.Count == 0)
            {
                List<OpenCifsServerShareInfo> implicitShareInfos = new List<OpenCifsServerShareInfo>
                {
                    CreateImplicitOptionsShareInfo(_Options)
                };

                if (exposeIpcShare)
                {
                    implicitShareInfos.Add(CreateIpcShareInfo());
                }

                return implicitShareInfos;
            }

            OpenCifsServerShareInfo[] configuredShareInfos = new OpenCifsServerShareInfo[_RegisteredShares.Count + (exposeIpcShare ? 1 : 0)];
            int shareIndex = 0;

            foreach (RegisteredShareRecord shareRecord in _RegisteredShares.Values)
            {
                configuredShareInfos[shareIndex++] = CreateShareInfo(
                    shareRecord.ShareName,
                    shareRecord.RootPath,
                    shareRecord.Backend.CreateRootIfMissing,
                    shareRecord.Backend.GetType().Name,
                    isImplicitOptionsShare: false,
                    shareRecord.Backend.Capabilities);
            }

            if (exposeIpcShare)
            {
                configuredShareInfos[shareIndex] = CreateIpcShareInfo();
            }

            return configuredShareInfos;
        }

        public bool HasAnyDfsReferrals()
        {
            return DfsReferralResolver.HasReferrals();
        }

        public Smb2ShareFlags GetShareFlags(string shareName, bool isNamedPipeShare)
        {
            if (isNamedPipeShare)
            {
                return Smb2ShareFlags.None;
            }

            List<OpenCifsServerDfsReferral>? referrals;
            return (_DfsReferralsByShare.TryGetValue(shareName, out referrals) && referrals != null && referrals.Count != 0)
                ? (Smb2ShareFlags.Dfs | Smb2ShareFlags.DfsRoot)
                : Smb2ShareFlags.None;
        }

        public bool TryGetEffectiveShare(string shareName, out RegisteredShareRecord? shareRecord)
        {
            if (_RegisteredShares.TryGetValue(shareName, out shareRecord))
            {
                return true;
            }

            if (ShouldExposeIpcShare() && string.Equals(shareName, IpcShareName, StringComparison.OrdinalIgnoreCase))
            {
                shareRecord = CreateNamedPipeShareRecord();
                return true;
            }

            if (_RegisteredShares.Count == 0 && string.Equals(shareName, _Options.ShareName, StringComparison.OrdinalIgnoreCase))
            {
                shareRecord = NormalizeRegisteredShare(
                    new OpenCifsServerFileSystemShare
                    {
                        ShareName = _Options.ShareName,
                        RootPath = _Options.SharePath,
                        CreateRootIfMissing = true
                    });
                return true;
            }

            shareRecord = null;
            return false;
        }

        private bool ShouldExposeIpcShare()
        {
            return _NamedPipeEndpoints.Count != 0 || HasAnyDfsReferrals();
        }

        private static RegisteredShareRecord CreateNamedPipeShareRecord()
        {
            return new RegisteredShareRecord
            {
                ShareName = IpcShareName,
                RootPath = NamedPipePseudoRootPath,
                Backend = null!,
                IsNamedPipeShare = true
            };
        }

        private static RegisteredShareRecord NormalizeRegisteredShare(OpenCifsServerShareBackend share)
        {
            share.Validate();

            string rootPath;

            try
            {
                rootPath = Path.GetFullPath(share.RootPath);
            }
            catch (Exception innerException)
            {
                throw new ArgumentException("RootPath could not be resolved to a filesystem location.", nameof(share), innerException);
            }

            if (share.CreateRootIfMissing)
            {
                Directory.CreateDirectory(rootPath);
            }

            return new RegisteredShareRecord
            {
                ShareName = share.ShareName,
                RootPath = rootPath,
                Backend = share.Clone(),
                IsNamedPipeShare = false
            };
        }

        private static OpenCifsServerShareInfo CreateIpcShareInfo()
        {
            return CreateShareInfo(
                IpcShareName,
                NamedPipePseudoRootPath,
                createRootIfMissing: false,
                nameof(OpenCifsServerNamedPipeEndpoint),
                isImplicitOptionsShare: false,
                new OpenCifsServerShareCapabilities
                {
                    SupportsFiles = false,
                    SupportsDirectories = false,
                    SupportsMetadata = false,
                    SupportsLocking = false,
                    SupportsNotifications = false,
                    SupportsNamedStreams = false
                });
        }

        private static OpenCifsServerShareInfo CreateImplicitOptionsShareInfo(OpenCifsServerOptions options)
        {
            return CreateShareInfo(
                options.ShareName,
                OpenCifsServerPathResolver.ResolveShareRootPath(options.SharePath),
                createRootIfMissing: true,
                nameof(OpenCifsServerFileSystemShare),
                isImplicitOptionsShare: true,
                new OpenCifsServerShareCapabilities
                {
                    SupportsFiles = true,
                    SupportsDirectories = true,
                    SupportsMetadata = true,
                    SupportsLocking = true,
                    SupportsNotifications = true,
                    SupportsNamedStreams = false
                });
        }

        private static OpenCifsServerShareInfo CreateShareInfo(
            string shareName,
            string rootPath,
            bool createRootIfMissing,
            string backendKind,
            bool isImplicitOptionsShare,
            OpenCifsServerShareCapabilities capabilities)
        {
            return new OpenCifsServerShareInfo(
                shareName,
                rootPath,
                createRootIfMissing,
                backendKind,
                isImplicitOptionsShare,
                capabilities);
        }
    }
}
