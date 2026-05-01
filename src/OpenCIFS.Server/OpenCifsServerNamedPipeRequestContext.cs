namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Request context for a named-pipe transceive operation hosted by OpenCIFS.
    /// </summary>
    public sealed class OpenCifsServerNamedPipeRequestContext
    {
        internal OpenCifsServerNamedPipeRequestContext(
            string serverName,
            ulong sessionId,
            uint treeId,
            string pipeName,
            string authenticatedUserName,
            string authenticatedUserDomain,
            SmbDialect? negotiatedDialect,
            ReadOnlyMemory<byte> inputBuffer,
            uint maxOutputResponse,
            IReadOnlyList<OpenCifsServerShareInfo> availableShares)
        {
            ServerName = serverName ?? throw new ArgumentNullException(nameof(serverName), "ServerName cannot be null.");
            PipeName = pipeName ?? throw new ArgumentNullException(nameof(pipeName), "PipeName cannot be null.");
            AuthenticatedUserName = authenticatedUserName ?? string.Empty;
            AuthenticatedUserDomain = authenticatedUserDomain ?? string.Empty;
            InputBuffer = inputBuffer;
            MaxOutputResponse = maxOutputResponse;
            AvailableShares = availableShares ?? throw new ArgumentNullException(nameof(availableShares), "AvailableShares cannot be null.");
            SessionId = sessionId;
            TreeId = treeId;
            NegotiatedDialect = negotiatedDialect;
        }

        /// <summary>
        /// Server name for the current OpenCIFS host.
        /// </summary>
        public string ServerName { get; }

        /// <summary>
        /// Authenticated session identifier.
        /// </summary>
        public ulong SessionId { get; }

        /// <summary>
        /// Tree identifier bound to the named-pipe share.
        /// </summary>
        public uint TreeId { get; }

        /// <summary>
        /// Named-pipe endpoint name.
        /// </summary>
        public string PipeName { get; }

        /// <summary>
        /// Authenticated user name.
        /// </summary>
        public string AuthenticatedUserName { get; }

        /// <summary>
        /// Authenticated user domain.
        /// </summary>
        public string AuthenticatedUserDomain { get; }

        /// <summary>
        /// Negotiated SMB dialect for the current session.
        /// </summary>
        public SmbDialect? NegotiatedDialect { get; }

        /// <summary>
        /// Input buffer passed through the named-pipe transceive operation.
        /// </summary>
        public ReadOnlyMemory<byte> InputBuffer { get; }

        /// <summary>
        /// Maximum output response length requested by the client.
        /// </summary>
        public uint MaxOutputResponse { get; }

        /// <summary>
        /// Immutable snapshots of the shares currently exposed by the local server definition.
        /// </summary>
        public IReadOnlyList<OpenCifsServerShareInfo> AvailableShares { get; }
    }
}
