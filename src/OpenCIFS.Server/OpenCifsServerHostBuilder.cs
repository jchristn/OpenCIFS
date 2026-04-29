namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;

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
                throw new InvalidOperationException("A share backend with the same name is already registered.");
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
        /// Build a host instance with the registered accounts and shares.
        /// </summary>
        /// <returns>Configured host.</returns>
        public OpenCifsServerHost BuildHost()
        {
            OpenCifsServerAccount[] accounts = _Accounts.ToArray();
            OpenCifsServerShareBackend[] shares = _Shares.ToArray();
            return CreateHost(accounts, shares);
        }

        /// <summary>
        /// Build a direct-TCP listener that creates one configured host per connection.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Configured direct-TCP listener.</returns>
        public OpenCifsDirectTcpServer BuildDirectTcpServer(Action<Exception>? exceptionHandler = null)
        {
            OpenCifsServerAccount[] accounts = _Accounts.ToArray();
            OpenCifsServerShareBackend[] shares = _Shares.ToArray();
            OpenCifsServerSharedState sharedState = new OpenCifsServerSharedState();
            return new OpenCifsDirectTcpServer(Options, () => CreateHost(accounts, shares, sharedState), exceptionHandler);
        }

        /// <summary>
        /// Build a managed direct-TCP application surface with explicit start and stop control.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Managed server application.</returns>
        public OpenCifsServerApplication BuildApplication(Action<Exception>? exceptionHandler = null)
        {
            return new OpenCifsServerApplication(Options, BuildDirectTcpServer(exceptionHandler));
        }

        private OpenCifsServerHost CreateHost(
            IReadOnlyList<OpenCifsServerAccount> accounts,
            IReadOnlyList<OpenCifsServerShareBackend> shares,
            OpenCifsServerSharedState? sharedState = null)
        {
            OpenCifsServerHost host = new OpenCifsServerHost(Options, sharedState);

            for (int shareIndex = 0; shareIndex < shares.Count; shareIndex++)
            {
                host.RegisterShare(shares[shareIndex]);
            }

            for (int accountIndex = 0; accountIndex < accounts.Count; accountIndex++)
            {
                host.RegisterAccount(accounts[accountIndex]);
            }

            return host;
        }

        private static OpenCifsServerAccount CloneAccount(OpenCifsServerAccount account)
        {
            return new OpenCifsServerAccount
            {
                UserName = account.UserName,
                UserDomain = account.UserDomain,
                Password = account.Password
            };
        }

        private readonly List<OpenCifsServerAccount> _Accounts = new List<OpenCifsServerAccount>();
        private readonly HashSet<string> _RegisteredShareNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private readonly List<OpenCifsServerShareBackend> _Shares = new List<OpenCifsServerShareBackend>();
    }
}
