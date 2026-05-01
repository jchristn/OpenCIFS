namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Primary OpenCIFS server builder surface.
    /// </summary>
    public sealed class OpenCifsServerBuilder
    {
        /// <summary>
        /// Initialize the primary OpenCIFS server builder with default options.
        /// </summary>
        public OpenCifsServerBuilder()
            : this(new OpenCifsServerOptions())
        {
        }

        /// <summary>
        /// Initialize the primary OpenCIFS server builder with explicit options.
        /// </summary>
        /// <param name="options">Server options.</param>
        public OpenCifsServerBuilder(OpenCifsServerOptions options)
        {
            _HostBuilder = new OpenCifsServerHostBuilder(options ?? throw new ArgumentNullException(nameof(options), "Options cannot be null."));
        }

        /// <summary>
        /// Mutable server options used by the builder.
        /// </summary>
        public OpenCifsServerOptions Options
        {
            get
            {
                return _HostBuilder.Options;
            }
        }

        /// <summary>
        /// Set the server display name.
        /// </summary>
        /// <param name="serverName">Server display name.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithServerName(string serverName)
        {
            Options.ServerName = serverName;
            return this;
        }

        /// <summary>
        /// Set the local bind address.
        /// </summary>
        /// <param name="bindAddress">Local bind address.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithBindAddress(string bindAddress)
        {
            Options.BindAddress = bindAddress;
            return this;
        }

        /// <summary>
        /// Set the local bind port.
        /// </summary>
        /// <param name="bindPort">Local bind port.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithBindPort(int bindPort)
        {
            Options.BindPort = bindPort;
            return this;
        }

        /// <summary>
        /// Set the supported dialect range.
        /// </summary>
        /// <param name="minimumDialect">Minimum negotiated dialect.</param>
        /// <param name="maximumDialect">Maximum negotiated dialect.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithDialectRange(SmbDialect minimumDialect, SmbDialect maximumDialect)
        {
            Options.MinimumDialect = minimumDialect;
            Options.MaximumDialect = maximumDialect;
            return this;
        }

        /// <summary>
        /// Set whether signing is required.
        /// </summary>
        /// <param name="requireSigning">Whether signing is required.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithSigningRequired(bool requireSigning = true)
        {
            Options.RequireSigning = requireSigning;
            return this;
        }

        /// <summary>
        /// Set whether SMB 3.x negotiation requires encryption-capable sessions.
        /// </summary>
        /// <param name="requireEncryptionForSmb3">Whether SMB 3.x negotiation requires encryption-capable sessions.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithSmb3EncryptionRequired(bool requireEncryptionForSmb3 = true)
        {
            Options.RequireEncryptionForSmb3 = requireEncryptionForSmb3;
            return this;
        }

        /// <summary>
        /// Enable the bounded SMB 3.1.1 preview slice on the server-side negotiate path.
        /// When enabled, the server allocates a SHA-512 preauth integrity transcript hash for
        /// SMB 3.1.1-shaped negotiate requests so the negotiate transcript is preserved for future
        /// session-key derivation wiring.
        /// </summary>
        /// <param name="enableSmb311Preview">Whether the SMB 3.1.1 preview is enabled.</param>
        /// <returns>The current builder.</returns>
        /// <remarks>
        /// The server's dialect-selection behavior continues to use the existing tolerance path until
        /// end-to-end SMB 3.1.1 wiring is complete, so opting in does not yet allow the server to
        /// negotiate SMB 3.1.1.
        /// </remarks>
        public OpenCifsServerBuilder WithSmb311Preview(bool enableSmb311Preview = true)
        {
            Options.EnableSmb311Preview = enableSmb311Preview;
            return this;
        }

        /// <summary>
        /// Configure optional request callbacks.
        /// </summary>
        /// <param name="callbacks">Request callbacks.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder ConfigureRequestCallbacks(OpenCifsServerRequestCallbacks callbacks)
        {
            _HostBuilder.ConfigureRequestCallbacks(callbacks);
            return this;
        }

        /// <summary>
        /// Configure an optional diagnostic logger.
        /// </summary>
        /// <param name="diagnosticLogger">Diagnostic logger.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder WithDiagnosticLogger(Action<string> diagnosticLogger)
        {
            Options.DiagnosticLogger = diagnosticLogger ?? throw new ArgumentNullException(nameof(diagnosticLogger), "DiagnosticLogger cannot be null.");
            return this;
        }

        /// <summary>
        /// Add an in-memory account registration.
        /// </summary>
        /// <param name="account">Account definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddAccount(OpenCifsServerAccount account)
        {
            _HostBuilder.AddAccount(account);
            return this;
        }

        /// <summary>
        /// Add a share registration through the primary share-builder surface.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="configure">Share configuration callback.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddShare(string shareName, Action<OpenCifsServerShareBuilder> configure)
        {
            if (configure == null)
            {
                throw new ArgumentNullException(nameof(configure), "Configure cannot be null.");
            }

            OpenCifsServerShareBuilder shareBuilder = new OpenCifsServerShareBuilder(shareName);
            configure(shareBuilder);
            _HostBuilder.AddShare(shareBuilder.Build());
            return this;
        }

        /// <summary>
        /// Add a built-in local filesystem-backed share registration.
        /// </summary>
        /// <param name="shareName">Share name.</param>
        /// <param name="rootPath">Backing filesystem root path.</param>
        /// <param name="createRootIfMissing">Whether the root should be created automatically.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddFileSystemShare(string shareName, string rootPath, bool createRootIfMissing = true)
        {
            return AddShare(shareName, share => share.UseLocalFileSystem(rootPath, createRootIfMissing));
        }

        /// <summary>
        /// Add a named-pipe endpoint registration under the implicit <c>IPC$</c> share.
        /// </summary>
        /// <param name="endpoint">Named-pipe endpoint definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddNamedPipeEndpoint(OpenCifsServerNamedPipeEndpoint endpoint)
        {
            _HostBuilder.AddNamedPipeEndpoint(endpoint);
            return this;
        }

        /// <summary>
        /// Add the bounded built-in SRVSVC share-enumeration endpoint under <c>IPC$</c>.
        /// </summary>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddSrvsvcShareEnumerationEndpoint()
        {
            _HostBuilder.AddSrvsvcShareEnumerationEndpoint();
            return this;
        }

        /// <summary>
        /// Add the bounded built-in UTF-8 echo endpoint under <c>IPC$</c>.
        /// </summary>
        /// <param name="pipeName">Optional endpoint name.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddUtf8EchoNamedPipeEndpoint(string pipeName = OpenCifsServerNamedPipeEndpoints.DefaultUtf8EchoPipeName)
        {
            _HostBuilder.AddUtf8EchoNamedPipeEndpoint(pipeName);
            return this;
        }

        /// <summary>
        /// Add a bounded DFS referral configuration.
        /// </summary>
        /// <param name="referral">DFS referral definition.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddDfsReferral(OpenCifsServerDfsReferral referral)
        {
            _HostBuilder.AddDfsReferral(referral);
            return this;
        }

        /// <summary>
        /// Add a bounded DFS referral configuration through the primary builder surface.
        /// </summary>
        /// <param name="namespaceShareName">Namespace share name.</param>
        /// <param name="namespacePath">Relative namespace path prefix.</param>
        /// <param name="targetShareName">Target share name.</param>
        /// <param name="targetPath">Relative target path beneath <paramref name="targetShareName" />.</param>
        /// <param name="targetServerName">Optional target server name. When omitted, the configured server name is used.</param>
        /// <param name="timeToLiveSeconds">Referral cache TTL in seconds.</param>
        /// <returns>The current builder.</returns>
        public OpenCifsServerBuilder AddDfsReferral(
            string namespaceShareName,
            string namespacePath,
            string targetShareName,
            string targetPath = "",
            string? targetServerName = null,
            uint timeToLiveSeconds = 300)
        {
            return AddDfsReferral(new OpenCifsServerDfsReferral
            {
                NamespaceShareName = namespaceShareName,
                NamespacePath = namespacePath,
                TargetServerName = string.IsNullOrWhiteSpace(targetServerName) ? Options.ServerName : targetServerName,
                TargetShareName = targetShareName,
                TargetPath = targetPath,
                TimeToLiveSeconds = timeToLiveSeconds
            });
        }

        /// <summary>
        /// Get immutable snapshots for the shares that a built server surface will expose.
        /// </summary>
        /// <returns>Available share snapshots.</returns>
        public IReadOnlyList<OpenCifsServerShareInfo> GetAvailableShares()
        {
            return _HostBuilder.GetAvailableShares();
        }

        /// <summary>
        /// Build immutable validated server settings.
        /// </summary>
        /// <returns>Immutable validated server settings.</returns>
        public OpenCifsServerSettings BuildSettings()
        {
            return OpenCifsServerSettings.FromOptions(Options);
        }

        /// <summary>
        /// Build an immutable configured server definition.
        /// </summary>
        /// <returns>The configured OpenCIFS server.</returns>
        public OpenCifsServer Build()
        {
            return _HostBuilder.BuildServer();
        }

        /// <summary>
        /// Build a configured server host.
        /// </summary>
        /// <returns>Configured server host.</returns>
        public OpenCifsServerHost BuildHost()
        {
            return Build().BuildHost();
        }

        /// <summary>
        /// Build a direct-TCP listener.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Configured direct-TCP listener.</returns>
        public OpenCifsDirectTcpServer BuildDirectTcpServer(Action<Exception>? exceptionHandler = null)
        {
            return Build().BuildDirectTcpServer(exceptionHandler);
        }

        /// <summary>
        /// Build a managed direct-TCP application surface.
        /// </summary>
        /// <param name="exceptionHandler">Optional per-connection exception handler.</param>
        /// <returns>Managed server application.</returns>
        public OpenCifsServerApplication BuildApplication(Action<Exception>? exceptionHandler = null)
        {
            return Build().BuildApplication(exceptionHandler);
        }

        private readonly OpenCifsServerHostBuilder _HostBuilder;
    }
}
