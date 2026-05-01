namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.IO;

    /// <summary>
    /// Bounded builder surface for listener creation, account registration, and share-backend registration.
    /// </summary>
    public sealed class OpenCifsServerHostBuilder
    {
        /// <summary>
        /// Initialize a server-host builder.
        /// </summary>
        /// <param name="options">Server options.</param>
        public OpenCifsServerHostBuilder(OpenCifsServerOptions options)
        {
            Options = options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            Options.Validate();
        }

        /// <summary>
        /// Server options used when building hosts and listeners.
        /// </summary>
        public OpenCifsServerOptions Options { get; }

        /// <summary>
        /// Add a registered in-memory account.
        /// </summary>
        /// <param name="account">Account definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddAccount(OpenCifsServerAccount account)
        {
            if (account == null)
            {
                throw new ArgumentNullException(nameof(account), "Account cannot be null.");
            }

            _Accounts.Add(CloneAccount(account));
            return this;
        }

        /// <summary>
        /// Add a generic share-backend registration.
        /// </summary>
        /// <param name="share">Share backend definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddShare(OpenCifsServerShareBackend share)
        {
            if (share == null)
            {
                throw new ArgumentNullException(nameof(share), "Share cannot be null.");
            }

            share.Validate();

            if (_RegisteredShareNames.Contains(share.ShareName))
            {
                throw new OpenCifsServerConfigurationException("A share backend with the same name is already registered.");
            }

            OpenCifsServerShareBackend clonedShare = share.Clone();
            _Shares.Add(clonedShare);
            _RegisteredShareNames.Add(clonedShare.ShareName);
            return this;
        }

        /// <summary>
        /// Add a local filesystem-backed share registration.
        /// </summary>
        /// <param name="share">Share definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddFileSystemShare(OpenCifsServerFileSystemShare share)
        {
            return AddShare(share);
        }

        /// <summary>
        /// Add a named-pipe endpoint registration under the implicit <c>IPC$</c> share.
        /// </summary>
        /// <param name="endpoint">Named-pipe endpoint definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoint endpoint)
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
            return this;
        }

        /// <summary>
        /// Add the bounded built-in SRVSVC share-enumeration endpoint under <c>IPC$</c>.
        /// </summary>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddSrvsvcShareEnumerationEndpoint()
        {
            return AddNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoints.CreateSrvsvcShareEnumerationEndpoint());
        }

        /// <summary>
        /// Add the bounded built-in UTF-8 echo endpoint under <c>IPC$</c>.
        /// </summary>
        /// <param name="pipeName">Optional endpoint name.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddUtf8EchoNamedPipeEndpoint(string pipeName = OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName)
        {
            return AddNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoints.CreateUtf8EchoEndpoint(pipeName));
        }

        /// <summary>
        /// Add a bounded DFS referral configuration.
        /// </summary>
        /// <param name="referral">DFS referral definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder AddDfsReferral(OpenCifsServerDfsReferral referral)
        {
            if (referral == null)
            {
                throw new ArgumentNullException(nameof(referral), "Referral cannot be null.");
            }

            OpenCifsServerDfsReferral clonedReferral = referral.Clone();

            if (_DfsReferrals.Exists(existing =>
                StringComparer.OrdinalIgnoreCase.Equals(existing.NamespaceShareName, clonedReferral.NamespaceShareName) &&
                StringComparer.OrdinalIgnoreCase.Equals(NormalizeDfsNamespacePath(existing.NamespacePath), NormalizeDfsNamespacePath(clonedReferral.NamespacePath)) &&
                StringComparer.OrdinalIgnoreCase.Equals(existing.TargetServerName, clonedReferral.TargetServerName) &&
                StringComparer.OrdinalIgnoreCase.Equals(existing.TargetShareName, clonedReferral.TargetShareName) &&
                StringComparer.OrdinalIgnoreCase.Equals(NormalizeDfsNamespacePath(existing.TargetPath), NormalizeDfsNamespacePath(clonedReferral.TargetPath))))
            {
                throw new OpenCifsServerConfigurationException("An equivalent DFS referral is already registered.");
            }

            _DfsReferrals.Add(clonedReferral);
            return this;
        }

        /// <summary>
        /// Configure optional application-control callbacks for selected request classes.
        /// </summary>
        /// <param name="callbacks">Callback definitions.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerHostBuilder ConfigureRequestCallbacks(OpenCifsServerRequestCallbacks callbacks)
        {
            Options.RequestCallbacks = callbacks ?? throw new ArgumentNullException(nameof(callbacks), "Callbacks cannot be null.");
            return this;
        }

        /// <summary>
        /// Build an immutable configured server definition.
        /// </summary>
        /// <returns>Configured server definition.</returns>
        public OpenCifsServer BuildServer()
        {
            return new OpenCifsServer(Options, _Accounts, _Shares, _NamedPipeEndpoints.Values, _DfsReferrals);
        }

        /// <summary>
        /// Build a host instance with the registered accounts and shares.
        /// </summary>
        /// <returns>Configured host.</returns>
        public OpenCifsServerHost BuildHost()
        {
            return BuildServer().BuildHost();
        }

        /// <summary>
        /// Build a direct-TCP listener that creates one configured host per connection.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Configured direct-TCP listener.</returns>
        public OpenCifsDirectTcpServer BuildDirectTcpServer(Action<Exception>? exceptionHandler = null)
        {
            return BuildServer().BuildDirectTcpServer(exceptionHandler);
        }

        /// <summary>
        /// Build a managed direct-TCP application surface with explicit start and stop control.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Managed server application.</returns>
        public OpenCifsServerApplication BuildApplication(Action<Exception>? exceptionHandler = null)
        {
            return BuildServer().BuildApplication(exceptionHandler);
        }

        /// <summary>
        /// Get immutable snapshots for the shares that a built server surface will expose.
        /// </summary>
        /// <returns>Available share snapshots.</returns>
        public IReadOnlyList<OpenCifsServerShareInfo> GetAvailableShares()
        {
            return CreateAvailableShares(Options, _Shares, _NamedPipeEndpoints.Values);
        }

        internal static OpenCifsServerShareInfo[] CreateAvailableShares(OpenCifsServerOptions options, IReadOnlyList<OpenCifsServerShareBackend> shares)
        {
            return CreateAvailableShares(options, shares, Array.Empty<OpenCifsServerNamedPipeEndpoint>());
        }

        internal static OpenCifsServerShareInfo[] CreateAvailableShares(OpenCifsServerOptions options, IReadOnlyList<OpenCifsServerShareBackend> shares, IReadOnlyCollection<OpenCifsServerNamedPipeEndpoint> namedPipeEndpoints)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            }

            if (shares == null)
            {
                throw new ArgumentNullException(nameof(shares), "Shares cannot be null.");
            }

            if (namedPipeEndpoints == null)
            {
                throw new ArgumentNullException(nameof(namedPipeEndpoints), "NamedPipeEndpoints cannot be null.");
            }

            if (shares.Count == 0)
            {
                List<OpenCifsServerShareInfo> implicitShareInfos = new List<OpenCifsServerShareInfo>
                {
                    CreateImplicitOptionsShareInfo(options)
                };

                if (namedPipeEndpoints.Count != 0)
                {
                    implicitShareInfos.Add(CreateImplicitIpcShareInfo());
                }

                return implicitShareInfos.ToArray();
            }

            OpenCifsServerShareInfo[] configuredShareInfos = new OpenCifsServerShareInfo[shares.Count + (namedPipeEndpoints.Count == 0 ? 0 : 1)];

            for (int index = 0; index < shares.Count; index++)
            {
                OpenCifsServerShareBackend share = shares[index];
                share.Validate();
                configuredShareInfos[index] = CreateShareInfo(
                    share.ShareName,
                    ResolveShareRootPath(share.RootPath),
                    share.CreateRootIfMissing,
                    share.GetType().Name,
                    isImplicitOptionsShare: false,
                    share.Capabilities);
            }

            if (namedPipeEndpoints.Count != 0)
            {
                configuredShareInfos[shares.Count] = CreateImplicitIpcShareInfo();
            }

            return configuredShareInfos;
        }

        internal static OpenCifsServerOptions CloneOptions(OpenCifsServerOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options), "Options cannot be null.");
            }

            return new OpenCifsServerOptions
            {
                ServerName = options.ServerName,
                BindAddress = options.BindAddress,
                BindPort = options.BindPort,
                ShareName = options.ShareName,
                SharePath = options.SharePath,
                MinimumDialect = options.MinimumDialect,
                MaximumDialect = options.MaximumDialect,
                RequireSigning = options.RequireSigning,
                RequireNtlmV2 = options.RequireNtlmV2,
                AllowAnonymous = options.AllowAnonymous,
                EnableSmb1 = options.EnableSmb1,
                RequireEncryptionForSmb3 = options.RequireEncryptionForSmb3,
                MaximumCredits = options.MaximumCredits,
                RequestCallbacks = options.RequestCallbacks,
                DiagnosticLogger = options.DiagnosticLogger,
                EnableSmb311Preview = options.EnableSmb311Preview
            };
        }

        internal static OpenCifsServerDfsReferral[] CloneDfsReferrals(IReadOnlyCollection<OpenCifsServerDfsReferral> referrals)
        {
            if (referrals == null)
            {
                throw new ArgumentNullException(nameof(referrals), "Referrals cannot be null.");
            }

            OpenCifsServerDfsReferral[] clones = new OpenCifsServerDfsReferral[referrals.Count];
            int index = 0;

            foreach (OpenCifsServerDfsReferral referral in referrals)
            {
                clones[index++] = referral.Clone();
            }

            return clones;
        }

        internal static OpenCifsServerAccount[] CloneAccounts(IReadOnlyList<OpenCifsServerAccount> accounts)
        {
            if (accounts == null)
            {
                throw new ArgumentNullException(nameof(accounts), "Accounts cannot be null.");
            }

            OpenCifsServerAccount[] clones = new OpenCifsServerAccount[accounts.Count];

            for (int index = 0; index < accounts.Count; index++)
            {
                clones[index] = CloneAccount(accounts[index] ?? throw new ArgumentException("Accounts cannot contain null entries.", nameof(accounts)));
            }

            return clones;
        }

        internal static OpenCifsServerShareBackend[] CloneShares(IReadOnlyList<OpenCifsServerShareBackend> shares)
        {
            if (shares == null)
            {
                throw new ArgumentNullException(nameof(shares), "Shares cannot be null.");
            }

            OpenCifsServerShareBackend[] clones = new OpenCifsServerShareBackend[shares.Count];

            for (int index = 0; index < shares.Count; index++)
            {
                OpenCifsServerShareBackend share = shares[index] ?? throw new ArgumentException("Shares cannot contain null entries.", nameof(shares));
                share.Validate();
                clones[index] = share.Clone();
            }

            return clones;
        }

        internal static OpenCifsServerNamedPipeEndpoint[] CloneNamedPipeEndpoints(IReadOnlyCollection<OpenCifsServerNamedPipeEndpoint> namedPipeEndpoints)
        {
            if (namedPipeEndpoints == null)
            {
                throw new ArgumentNullException(nameof(namedPipeEndpoints), "NamedPipeEndpoints cannot be null.");
            }

            OpenCifsServerNamedPipeEndpoint[] clones = new OpenCifsServerNamedPipeEndpoint[namedPipeEndpoints.Count];
            int index = 0;

            foreach (OpenCifsServerNamedPipeEndpoint endpoint in namedPipeEndpoints)
            {
                clones[index++] = endpoint ?? throw new ArgumentException("NamedPipeEndpoints cannot contain null entries.", nameof(namedPipeEndpoints));
            }

            return clones;
        }

        internal static OpenCifsServerAccount CloneAccount(OpenCifsServerAccount account)
        {
            if (account == null)
            {
                throw new ArgumentNullException(nameof(account), "Account cannot be null.");
            }

            return new OpenCifsServerAccount
            {
                UserName = account.UserName,
                UserDomain = account.UserDomain,
                Password = account.Password
            };
        }

        internal static OpenCifsServerShareInfo[] CopyAvailableShares(IReadOnlyList<OpenCifsServerShareInfo> shares)
        {
            if (shares == null)
            {
                throw new ArgumentNullException(nameof(shares), "Shares cannot be null.");
            }

            OpenCifsServerShareInfo[] copies = new OpenCifsServerShareInfo[shares.Count];

            for (int index = 0; index < shares.Count; index++)
            {
                copies[index] = shares[index] ?? throw new ArgumentException("Shares cannot contain null entries.", nameof(shares));
            }

            return copies;
        }

        private static OpenCifsServerShareInfo CreateImplicitOptionsShareInfo(OpenCifsServerOptions options)
        {
            return CreateShareInfo(
                options.ShareName,
                ResolveShareRootPath(options.SharePath),
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

        private static OpenCifsServerShareInfo CreateImplicitIpcShareInfo()
        {
            return CreateShareInfo(
                "IPC$",
                "[named-pipes]",
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

        private static string ResolveShareRootPath(string rootPath)
        {
            try
            {
                return Path.GetFullPath(rootPath);
            }
            catch (Exception exception)
            {
                throw new ArgumentException("RootPath could not be resolved to a filesystem location.", nameof(rootPath), exception);
            }
        }

        private static string NormalizeDfsNamespacePath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path == "/" || path == "\\")
            {
                return string.Empty;
            }

            return path.Trim().Replace('/', '\\').Trim('\\');
        }

        private readonly List<OpenCifsServerAccount> _Accounts = new List<OpenCifsServerAccount>();
        private readonly Dictionary<string, OpenCifsServerNamedPipeEndpoint> _NamedPipeEndpoints = new Dictionary<string, OpenCifsServerNamedPipeEndpoint>(StringComparer.OrdinalIgnoreCase);
        private readonly List<OpenCifsServerDfsReferral> _DfsReferrals = new List<OpenCifsServerDfsReferral>();
        private readonly HashSet<string> _RegisteredShareNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<OpenCifsServerShareBackend> _Shares = new List<OpenCifsServerShareBackend>();
    }
}

