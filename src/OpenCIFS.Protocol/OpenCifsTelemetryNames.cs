namespace OpenCIFS.Protocol
{
    /// <summary>
    /// Stable telemetry names emitted by the OpenCIFS client and server libraries.
    /// </summary>
    /// <remarks>
    /// These strings are a public contract consumed by collectors, dashboards, and alerts. The libraries emit through the
    /// base-class-library <c>System.Diagnostics.Metrics.Meter</c> and <c>System.Diagnostics.ActivitySource</c> types only,
    /// so nothing is recorded or exported unless the host subscribes to <see cref="ServerMeterName" />,
    /// <see cref="ServerActivitySourceName" />, <see cref="ClientMeterName" />, or <see cref="ClientActivitySourceName" />.
    /// Instrument names are dotted OpenTelemetry-style names; a Prometheus exporter rewrites them to snake case with unit
    /// suffixes (for example <c>opencifs.server.command.duration</c> becomes <c>opencifs_server_command_duration_seconds</c>).
    /// All members are constants and are safe to read from any thread.
    /// </remarks>
    public static class OpenCifsTelemetryNames
    {
        /// <summary>
        /// Meter name used by <c>OpenCIFS.Server</c>.
        /// </summary>
        public const string ServerMeterName = "OpenCIFS.Server";

        /// <summary>
        /// Activity source name used by <c>OpenCIFS.Server</c>.
        /// </summary>
        public const string ServerActivitySourceName = "OpenCIFS.Server";

        /// <summary>
        /// Meter name used by <c>OpenCIFS.Client</c>.
        /// </summary>
        public const string ClientMeterName = "OpenCIFS.Client";

        /// <summary>
        /// Activity source name used by <c>OpenCIFS.Client</c>.
        /// </summary>
        public const string ClientActivitySourceName = "OpenCIFS.Client";

        /// <summary>
        /// Gauge that reports 1 per loaded OpenCIFS component, labeled with the component and its assembly version.
        /// </summary>
        public const string BuildInfo = "opencifs.build.info";

        /// <summary>
        /// Counter of TCP connections accepted by the server.
        /// </summary>
        public const string ServerConnectionsAccepted = "opencifs.server.connections.accepted";

        /// <summary>
        /// Up-down counter of TCP connections currently open on the server.
        /// </summary>
        public const string ServerConnectionsActive = "opencifs.server.connections.active";

        /// <summary>
        /// Counter of server connections closed, labeled by close reason.
        /// </summary>
        public const string ServerConnectionsClosed = "opencifs.server.connections.closed";

        /// <summary>
        /// Histogram of server connection lifetimes in seconds, labeled by close reason.
        /// </summary>
        public const string ServerConnectionDuration = "opencifs.server.connection.duration";

        /// <summary>
        /// Up-down counter of server listeners currently running.
        /// </summary>
        public const string ServerListenersActive = "opencifs.server.listeners.active";

        /// <summary>
        /// Gauge that reports 1 per running listener, labeled with safe, bounded configuration values.
        /// </summary>
        public const string ServerListenerInfo = "opencifs.server.listener.info";

        /// <summary>
        /// Histogram of end-to-end inbound packet handling time in seconds (queued, decode, dispatch, encode, send).
        /// </summary>
        public const string ServerPacketDuration = "opencifs.server.packet.duration";

        /// <summary>
        /// Histogram of inbound packet handling time per stage in seconds.
        /// </summary>
        public const string ServerPacketStageDuration = "opencifs.server.packet.stage.duration";

        /// <summary>
        /// Up-down counter of inbound packets waiting for the server-wide state lock.
        /// </summary>
        public const string ServerLockWaiting = "opencifs.server.lock.waiting";

        /// <summary>
        /// Histogram of per-command server handling time in seconds, labeled by command, NT status, and outcome.
        /// </summary>
        public const string ServerCommandDuration = "opencifs.server.command.duration";

        /// <summary>
        /// Counter of server-side failures, labeled by exception type and the stage that raised it.
        /// </summary>
        public const string ServerErrors = "opencifs.server.errors";

        /// <summary>
        /// Counter of completed SMB2 dialect negotiations, labeled by negotiated dialect.
        /// </summary>
        public const string ServerNegotiations = "opencifs.server.negotiations";

        /// <summary>
        /// Counter of completed session authentication attempts, labeled by mechanism, outcome, and session kind.
        /// </summary>
        public const string ServerAuthAttempts = "opencifs.server.auth.attempts";

        /// <summary>
        /// Gauge of authenticated or authenticating sessions currently held by the server.
        /// </summary>
        public const string ServerSessionsActive = "opencifs.server.sessions.active";

        /// <summary>
        /// Gauge of tree connects currently held by the server.
        /// </summary>
        public const string ServerTreesActive = "opencifs.server.trees.active";

        /// <summary>
        /// Gauge of file, directory, and named-pipe opens currently held by the server.
        /// </summary>
        public const string ServerOpensActive = "opencifs.server.opens.active";

        /// <summary>
        /// Gauge of durable opens detached from a lost connection and awaiting reconnect.
        /// </summary>
        public const string ServerDurableOpensDetached = "opencifs.server.durable_opens.detached";

        /// <summary>
        /// Counter of durable-handle reconnect attempts, labeled by outcome.
        /// </summary>
        public const string ServerDurableReconnects = "opencifs.server.durable_reconnects";

        /// <summary>
        /// Gauge of pending SMB2 CHANGE_NOTIFY subscriptions.
        /// </summary>
        public const string ServerChangeNotifyPending = "opencifs.server.change_notify.pending";

        /// <summary>
        /// Gauge of server-initiated asynchronous responses queued but not yet written to their connection.
        /// </summary>
        public const string ServerAsyncResponsesQueued = "opencifs.server.async_responses.queued";

        /// <summary>
        /// Counter of server-initiated asynchronous responses written, labeled by kind.
        /// </summary>
        public const string ServerAsyncResponsesSent = "opencifs.server.async_responses.sent";

        /// <summary>
        /// Histogram of the time an asynchronous response waited between being queued and being written, in seconds.
        /// </summary>
        public const string ServerAsyncResponseQueueDuration = "opencifs.server.async_response.queue.duration";

        /// <summary>
        /// Histogram of share-backend storage call time in seconds, labeled by storage operation and outcome.
        /// </summary>
        public const string ServerStorageDuration = "opencifs.server.storage.duration";

        /// <summary>
        /// Counter of file data bytes served by READ and accepted by WRITE, labeled by direction.
        /// </summary>
        public const string ServerIoBytes = "opencifs.server.io.bytes";

        /// <summary>
        /// Counter of SMB transport payload bytes received and transmitted by the server.
        /// </summary>
        public const string ServerNetworkIo = "opencifs.server.network.io";

        /// <summary>
        /// Histogram of public client operation time in seconds, labeled by operation, outcome, and error type.
        /// </summary>
        public const string ClientOperationDuration = "opencifs.client.operation.duration";

        /// <summary>
        /// Histogram of the time a client operation waited for the per-connection operation lock, in seconds.
        /// </summary>
        public const string ClientOperationQueueDuration = "opencifs.client.operation.queue.duration";

        /// <summary>
        /// Up-down counter of client operations waiting for the per-connection operation lock.
        /// </summary>
        public const string ClientOperationsWaiting = "opencifs.client.operations.waiting";

        /// <summary>
        /// Histogram of client SMB2 request round-trip time in seconds, labeled by command, NT status, and outcome.
        /// </summary>
        public const string ClientRequestDuration = "opencifs.client.request.duration";

        /// <summary>
        /// Histogram of client connect-and-negotiate time in seconds, labeled by outcome and error type.
        /// </summary>
        public const string ClientConnectDuration = "opencifs.client.connect.duration";

        /// <summary>
        /// Up-down counter of client connections currently established.
        /// </summary>
        public const string ClientConnectionsActive = "opencifs.client.connections.active";

        /// <summary>
        /// Counter of client transport losses, labeled by exception type.
        /// </summary>
        public const string ClientTransportFailures = "opencifs.client.transport.failures";

        /// <summary>
        /// Counter of client requests abandoned because the caller cancelled while awaiting the response.
        /// </summary>
        public const string ClientRequestsAbandoned = "opencifs.client.requests.abandoned";

        /// <summary>
        /// Counter of file data bytes read and written by the client, labeled by direction.
        /// </summary>
        public const string ClientIoBytes = "opencifs.client.io.bytes";

        /// <summary>
        /// Counter of SMB transport payload bytes received and transmitted by the client.
        /// </summary>
        public const string ClientNetworkIo = "opencifs.client.network.io";

        /// <summary>
        /// Attribute key for the OpenCIFS component (<c>server</c> or <c>client</c>).
        /// </summary>
        public const string AttributeComponent = "opencifs.component";

        /// <summary>
        /// Attribute key for the OpenCIFS assembly version.
        /// </summary>
        public const string AttributeVersion = "opencifs.version";

        /// <summary>
        /// Attribute key for the SMB2 command in upper snake case (for example <c>QUERY_DIRECTORY</c>).
        /// </summary>
        public const string AttributeCommand = "smb.command";

        /// <summary>
        /// Attribute key for the NT status name in upper snake case (for example <c>ACCESS_DENIED</c>), or <c>OTHER</c>.
        /// </summary>
        public const string AttributeStatus = "smb.status";

        /// <summary>
        /// Attribute key for the negotiated SMB dialect (for example <c>3.0.2</c>).
        /// </summary>
        public const string AttributeDialect = "smb.dialect";

        /// <summary>
        /// Attribute key for the operation outcome (<c>success</c>, <c>warning</c>, <c>error</c>, <c>exception</c>, or <c>cancelled</c>).
        /// </summary>
        public const string AttributeOutcome = "outcome";

        /// <summary>
        /// Attribute key for the exception type name on failures.
        /// </summary>
        public const string AttributeErrorType = "error.type";

        /// <summary>
        /// Attribute key for the stage name (<c>queued</c>, <c>decode</c>, <c>dispatch</c>, <c>encode</c>, <c>send</c>, and so on).
        /// </summary>
        public const string AttributeStage = "stage";

        /// <summary>
        /// Attribute key for the connection close reason.
        /// </summary>
        public const string AttributeCloseReason = "reason";

        /// <summary>
        /// Attribute key for the inbound packet kind (<c>smb2</c>, <c>smb2_compound</c>, <c>smb1_negotiate</c>).
        /// </summary>
        public const string AttributePacketKind = "smb.packet.kind";

        /// <summary>
        /// Attribute key for the authentication mechanism (<c>ntlm</c>, <c>spnego_ntlm</c>, <c>legacy_ntlm</c>, <c>kerberos</c>).
        /// </summary>
        public const string AttributeAuthMechanism = "auth.mechanism";

        /// <summary>
        /// Attribute key for the authenticated session kind (<c>user</c>, <c>guest</c>, <c>anonymous</c>, <c>none</c>).
        /// </summary>
        public const string AttributeSessionKind = "smb.session.kind";

        /// <summary>
        /// Attribute key for the asynchronous response kind (<c>oplock_break</c>, <c>lease_break</c>, <c>change_notify</c>, and so on).
        /// </summary>
        public const string AttributeAsyncKind = "smb.async.kind";

        /// <summary>
        /// Attribute key for the share-backend storage operation (<c>open</c>, <c>read</c>, <c>write</c>, and so on).
        /// </summary>
        public const string AttributeStorageOperation = "storage.operation";

        /// <summary>
        /// Attribute key for the file data direction (<c>read</c> or <c>write</c>).
        /// </summary>
        public const string AttributeIoDirection = "smb.io.direction";

        /// <summary>
        /// Attribute key for the network direction (<c>receive</c> or <c>transmit</c>), per OpenTelemetry semantic conventions.
        /// </summary>
        public const string AttributeNetworkIoDirection = "network.io.direction";

        /// <summary>
        /// Attribute key for the public client operation name (for example <c>Read</c>, <c>TreeConnect</c>).
        /// </summary>
        public const string AttributeOperation = "opencifs.operation";

        /// <summary>
        /// Attribute key for the listening or remote server port.
        /// </summary>
        public const string AttributeServerPort = "server.port";

        /// <summary>
        /// Attribute key for the minimum enabled dialect on listener info.
        /// </summary>
        public const string AttributeMinimumDialect = "smb.dialect.min";

        /// <summary>
        /// Attribute key for the maximum enabled dialect on listener info.
        /// </summary>
        public const string AttributeMaximumDialect = "smb.dialect.max";

        /// <summary>
        /// Attribute key for whether signing is required on listener info.
        /// </summary>
        public const string AttributeRequireSigning = "smb.signing.required";

        /// <summary>
        /// Attribute key for whether SMB 3.x encryption is required on listener info.
        /// </summary>
        public const string AttributeRequireEncryption = "smb.encryption.required";

        /// <summary>
        /// Attribute key for whether anonymous sessions are allowed on listener info.
        /// </summary>
        public const string AttributeAllowAnonymous = "smb.anonymous.allowed";

        /// <summary>
        /// Attribute key for whether the SMB1 negotiate bridge is enabled on listener info.
        /// </summary>
        public const string AttributeEnableSmb1 = "smb.smb1.enabled";

        /// <summary>
        /// Span attribute key for the SMB2 message identifier (spans only, never metrics).
        /// </summary>
        public const string SpanAttributeMessageId = "smb.message_id";

        /// <summary>
        /// Span attribute key for the SMB2 session identifier (spans only, never metrics).
        /// </summary>
        public const string SpanAttributeSessionId = "smb.session_id";

        /// <summary>
        /// Span attribute key for the SMB2 tree identifier (spans only, never metrics).
        /// </summary>
        public const string SpanAttributeTreeId = "smb.tree_id";

        /// <summary>
        /// Span attribute key for the number of entries in a compounded packet.
        /// </summary>
        public const string SpanAttributeCompoundCount = "smb.compound.count";

        /// <summary>
        /// Span attribute key for whether the inbound packet was SMB 3.x encrypted.
        /// </summary>
        public const string SpanAttributeEncrypted = "smb.encrypted";

        /// <summary>
        /// Span attribute key for the remote peer address (spans only, never metrics).
        /// </summary>
        public const string SpanAttributePeerAddress = "network.peer.address";

        /// <summary>
        /// Span attribute key for the remote peer port (spans only, never metrics).
        /// </summary>
        public const string SpanAttributePeerPort = "network.peer.port";

        /// <summary>
        /// Span attribute key for the configured server host name on client spans.
        /// </summary>
        public const string SpanAttributeServerAddress = "server.address";

        /// <summary>
        /// Span attribute key for the transport protocol (always <c>tcp</c>).
        /// </summary>
        public const string SpanAttributeNetworkTransport = "network.transport";

        /// <summary>
        /// Span attribute key for the number of bytes requested or transferred by a file data operation.
        /// </summary>
        public const string SpanAttributeByteCount = "smb.io.bytes";
    }
}
