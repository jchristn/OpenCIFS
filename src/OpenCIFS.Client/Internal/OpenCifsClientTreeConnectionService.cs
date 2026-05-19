namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientTreeConnectionService
    {
        public OpenCifsClientTreeConnectionService(
            Func<OpenCifsClientSession> getSession,
            Action ensureAuthenticatedSession,
            Action<OpenCifsClientTreeHandle> validateTreeHandle,
            Action<OpenCifsClientTreeHandle> markTreeDisconnected,
            Func<string, uint, Smb2ShareFlags, OpenCifsClientTreeHandle> createTrackedTreeHandle,
            Func<Task> resetTransportAsync,
            Action resetSession,
            Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> sendSingleRequestAsync)
        {
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
            _EnsureAuthenticatedSession = ensureAuthenticatedSession ?? throw new ArgumentNullException(nameof(ensureAuthenticatedSession), "EnsureAuthenticatedSession cannot be null.");
            _ValidateTreeHandle = validateTreeHandle ?? throw new ArgumentNullException(nameof(validateTreeHandle), "ValidateTreeHandle cannot be null.");
            _MarkTreeDisconnected = markTreeDisconnected ?? throw new ArgumentNullException(nameof(markTreeDisconnected), "MarkTreeDisconnected cannot be null.");
            _CreateTrackedTreeHandle = createTrackedTreeHandle ?? throw new ArgumentNullException(nameof(createTrackedTreeHandle), "CreateTrackedTreeHandle cannot be null.");
            _ResetTransportAsync = resetTransportAsync ?? throw new ArgumentNullException(nameof(resetTransportAsync), "ResetTransportAsync cannot be null.");
            _ResetSession = resetSession ?? throw new ArgumentNullException(nameof(resetSession), "ResetSession cannot be null.");
            _SendSingleRequestAsync = sendSingleRequestAsync ?? throw new ArgumentNullException(nameof(sendSingleRequestAsync), "SendSingleRequestAsync cannot be null.");
        }

        public async Task<OpenCifsClientTreeHandle> TreeConnectAsync(string shareName, CancellationToken cancellationToken)
        {
            _EnsureAuthenticatedSession();

            if (string.IsNullOrWhiteSpace(shareName))
            {
                throw new ArgumentNullException(nameof(shareName), "ShareName cannot be null or whitespace.");
            }

            OpenCifsClientSession session = _GetSession();
            string normalizedShareName = shareName.Trim('\\');
            Smb2TreeConnectRequest request = session.CreateTreeConnectRequest(normalizedShareName);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.TreeConnect, sessionId: session.SessionId!.Value);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;
            Smb2TreeConnectResponse treeConnectResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                responseHeader.Status,
                responsePayload,
                Smb2TreeConnectResponse.ReadFrom);
            session.ApplyTreeConnectResult(
                normalizedShareName,
                responseHeader.TreeId,
                responseHeader.Status,
                treeConnectResponse);

            if (ShouldValidateSecureNegotiate(session) && !session.IsSecureNegotiateValidated)
            {
                try
                {
                    await ValidateSecureNegotiateCoreAsync(responseHeader.TreeId, cancellationToken).ConfigureAwait(false);
                }
                catch
                {
                    await ResetTransportAndSessionAsync().ConfigureAwait(false);
                    throw;
                }
            }

            return _CreateTrackedTreeHandle(
                normalizedShareName,
                responseHeader.TreeId,
                (Smb2ShareFlags)treeConnectResponse.ShareFlags);
        }

        public async Task ValidateSecureNegotiateAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken)
        {
            _ValidateTreeHandle(treeHandle);
            OpenCifsClientSession session = _GetSession();

            if (!ShouldValidateSecureNegotiate(session))
            {
                return;
            }

            try
            {
                await ValidateSecureNegotiateCoreAsync(treeHandle.TreeId, cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                await ResetTransportAndSessionAsync().ConfigureAwait(false);
                throw;
            }
        }

        public async Task TreeDisconnectAsync(OpenCifsClientTreeHandle treeHandle, CancellationToken cancellationToken)
        {
            _ValidateTreeHandle(treeHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2TreeDisconnectRequest request = session.CreateTreeDisconnectRequest(treeHandle.TreeId);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.TreeDisconnect, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;
            session.ApplyTreeDisconnectResult(
                treeHandle.TreeId,
                responseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseHeader.Status,
                    responsePayload,
                    Smb2TreeDisconnectResponse.ReadFrom));
            _MarkTreeDisconnected(treeHandle);
        }

        private async Task ValidateSecureNegotiateCoreAsync(uint treeId, CancellationToken cancellationToken)
        {
            OpenCifsClientSession session = _GetSession();
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.Ioctl, treeId, sessionId: session.SessionId!.Value);
            Smb2IoctlRequest request = session.CreateValidateNegotiateInfoRequest(maxOutputResponse: 256);
            OpenCifsClientRequestResponse responseEnvelope = await _SendSingleRequestAsync(requestHeader, request.ToByteArray(), cancellationToken).ConfigureAwait(false);
            Smb2Header responseHeader = responseEnvelope.ResponseHeader;
            byte[] responsePayload = responseEnvelope.ResponsePayload;
            session.ApplyValidateNegotiateInfoResult(
                responseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseHeader.Status,
                    responsePayload,
                    Smb2IoctlResponse.ReadFrom));
        }

        private async Task ResetTransportAndSessionAsync()
        {
            await _ResetTransportAsync().ConfigureAwait(false);
            _ResetSession();
        }

        private static bool ShouldValidateSecureNegotiate(OpenCifsClientSession session)
        {
            return session.NegotiatedDialect.HasValue &&
                session.NegotiatedDialect.Value >= SmbDialect.Smb30;
        }

        private readonly Func<OpenCifsClientSession> _GetSession;
        private readonly Action _EnsureAuthenticatedSession;
        private readonly Action<OpenCifsClientTreeHandle> _ValidateTreeHandle;
        private readonly Action<OpenCifsClientTreeHandle> _MarkTreeDisconnected;
        private readonly Func<string, uint, Smb2ShareFlags, OpenCifsClientTreeHandle> _CreateTrackedTreeHandle;
        private readonly Func<Task> _ResetTransportAsync;
        private readonly Action _ResetSession;
        private readonly Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> _SendSingleRequestAsync;
    }
}
