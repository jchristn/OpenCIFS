namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Immutable configured OpenCIFS server definition that can build managed applications and advanced listeners.
    /// </summary>
    public sealed class OpenCifsServer
    {
        internal OpenCifsServer(
            OpenCifsServerOptions options,
            IReadOnlyList<OpenCifsServerAccount> accounts,
            IReadOnlyList<OpenCifsServerShareBackend> shares,
            IReadOnlyCollection<OpenCifsServerNamedPipeEndpoint> namedPipeEndpoints,
            IReadOnlyCollection<OpenCifsServerDfsReferral> dfsReferrals)
        {
            _Options = OpenCifsServerHostBuilder.CloneOptions(options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null."));
            _Accounts = OpenCifsServerHostBuilder.CloneAccounts(accounts);
            _Shares = OpenCifsServerHostBuilder.CloneShares(shares);
            _NamedPipeEndpoints = OpenCifsServerHostBuilder.CloneNamedPipeEndpoints(namedPipeEndpoints ?? throw new ArgumentNullException(nameof(namedPipeEndpoints), "NamedPipeEndpoints cannot be null."));
            _DfsReferrals = OpenCifsServerHostBuilder.CloneDfsReferrals(dfsReferrals ?? throw new ArgumentNullException(nameof(dfsReferrals), "DfsReferrals cannot be null."));
            _AvailableShares = OpenCifsServerHostBuilder.CopyAvailableShares(OpenCifsServerHostBuilder.CreateAvailableShares(_Options, _Shares, _NamedPipeEndpoints));
            Settings = OpenCifsServerSettings.FromOptions(_Options);
        }

        /// <summary>
        /// Immutable validated server settings snapshot.
        /// </summary>
        public OpenCifsServerSettings Settings { get; }

        /// <summary>
        /// Immutable snapshots for the shares that this configured server definition will expose.
        /// </summary>
        public IReadOnlyList<OpenCifsServerShareInfo> AvailableShares
        {
            get
            {
                return _AvailableShares;
            }
        }

        /// <summary>
        /// Get immutable snapshots for the shares that this configured server definition will expose.
        /// </summary>
        /// <returns>Available share snapshots.</returns>
        public IReadOnlyList<OpenCifsServerShareInfo> GetAvailableShares()
        {
            return _AvailableShares;
        }

        /// <summary>
        /// Build a configured host instance.
        /// </summary>
        /// <returns>Configured host.</returns>
        public OpenCifsServerHost BuildHost()
        {
            return CreateHost();
        }

        /// <summary>
        /// Build a direct-TCP listener that creates one configured host per connection.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Configured direct-TCP listener.</returns>
        public OpenCifsDirectTcpServer BuildDirectTcpServer(Action<Exception>? exceptionHandler = null)
        {
            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
            return new OpenCifsDirectTcpServer(_Options, () => CreateHost(sharedState), exceptionHandler);
        }

        /// <summary>
        /// Build a managed direct-TCP application surface with explicit start and stop control.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Managed server application.</returns>
        public OpenCifsServerApplication BuildApplication(Action<Exception>? exceptionHandler = null)
        {
            return new OpenCifsServerApplication(_Options, BuildDirectTcpServer(exceptionHandler), _AvailableShares);
        }

        private OpenCifsServerHost CreateHost(OpenCifsServerSharedState? sharedState = null)
        {
            OpenCifsServerHost host = new OpenCifsServerHost(_Options, sharedState);

            for (int shareIndex = 0; shareIndex < _Shares.Length; shareIndex++)
            {
                host.RegisterShare(_Shares[shareIndex].Clone());
            }

            for (int endpointIndex = 0; endpointIndex < _NamedPipeEndpoints.Length; endpointIndex++)
            {
                host.RegisterNamedPipeEndpoint(_NamedPipeEndpoints[endpointIndex]);
            }

            for (int referralIndex = 0; referralIndex < _DfsReferrals.Length; referralIndex++)
            {
                host.RegisterDfsReferral(_DfsReferrals[referralIndex].Clone());
            }

            for (int accountIndex = 0; accountIndex < _Accounts.Length; accountIndex++)
            {
                host.RegisterAccount(OpenCifsServerHostBuilder.CloneAccount(_Accounts[accountIndex]));
            }

            return host;
        }

        private readonly OpenCifsServerAccount[] _Accounts;
        private readonly OpenCifsServerDfsReferral[] _DfsReferrals;
        private readonly OpenCifsServerNamedPipeEndpoint[] _NamedPipeEndpoints;
        private readonly OpenCifsServerOptions _Options;
        private readonly OpenCifsServerShareInfo[] _AvailableShares;
        private readonly OpenCifsServerShareBackend[] _Shares;
    }
}
