namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using OpenCIFS.Transport;

    internal sealed class OpenCifsClientRequestDispatchService
    {
        public OpenCifsClientRequestDispatchService(
            Func<FramedPipeConnection?> getConnection,
            Func<OpenCifsClientSession> getSession)
        {
            _GetConnection = getConnection ?? throw new ArgumentNullException(nameof(getConnection), "GetConnection cannot be null.");
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
        }

        public async Task<OpenCifsClientRequestResponse> SendSingleRequestAsync(
            Smb2Header requestHeader,
            byte[] requestPayload,
            CancellationToken cancellationToken)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            if (requestPayload == null)
            {
                throw new ArgumentNullException(nameof(requestPayload), "RequestPayload cannot be null.");
            }

            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(requestHeader, requestPayload)
            });

            await WriteRequestPacketAsync(requestPacket, cancellationToken).ConfigureAwait(false);

            while (true)
            {
                byte[] responseBytes = await ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
                OpenCifsClientSession session = _GetSession();
                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);

                if (requestHeader.Command != Smb2Command.SessionSetup)
                {
                    session.ValidateResponsePacket(responsePacket, responseBytes);
                }

                if (responsePacket.Entries.Count != 1)
                {
                    throw new OpenCifsClientProtocolException("The managed direct-TCP client connection expects one SMB2 response per request in the current slice.");
                }

                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];

                if (responseEntry.Header.Command != requestHeader.Command)
                {
                    throw new OpenCifsClientProtocolException("The server response command does not match the request command.");
                }

                session.ApplyResponseHeader(responseEntry.Header);

                if (responseEntry.Header.Status == NtStatus.Pending)
                {
                    if ((responseEntry.Header.Flags & Smb2HeaderFlags.AsyncCommand) == 0)
                    {
                        throw new OpenCifsClientProtocolException("The managed direct-TCP client connection does not support synchronous STATUS_PENDING SMB2 responses.");
                    }

                    continue;
                }

                return new OpenCifsClientRequestResponse(
                    responseEntry.Header,
                    OpenCifsClientResponseDecoder.GetResponsePayloadBytes(responseEntry));
            }
        }

        public async Task<Smb2CompoundPacket> SendCompoundRequestAsync(Smb2CompoundPacket requestPacket, CancellationToken cancellationToken)
        {
            if (requestPacket == null)
            {
                throw new ArgumentNullException(nameof(requestPacket), "RequestPacket cannot be null.");
            }

            await WriteRequestPacketAsync(requestPacket, cancellationToken).ConfigureAwait(false);
            byte[] responseBytes = await ReadNextResponsePacketBytesAsync(cancellationToken).ConfigureAwait(false);
            OpenCifsClientSession session = _GetSession();
            Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
            session.ValidateResponsePacket(responsePacket, responseBytes);
            session.ApplyCompoundResponsePacket(responsePacket);
            return responsePacket;
        }

        public async Task<OpenCifsClientChangeNotifyRequestResponse> SendChangeNotifyRequestAsync(
            Smb2Header requestHeader,
            byte[] requestPayload,
            CancellationToken cancellationToken)
        {
            if (requestHeader == null)
            {
                throw new ArgumentNullException(nameof(requestHeader), "RequestHeader cannot be null.");
            }

            if (requestPayload == null)
            {
                throw new ArgumentNullException(nameof(requestPayload), "RequestPayload cannot be null.");
            }

            Smb2CompoundPacket requestPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(requestHeader, requestPayload)
            });

            await WriteRequestPacketAsync(requestPacket, cancellationToken).ConfigureAwait(false);

            bool cancellationRequested = false;
            bool cancelIssued = false;
            bool pendingResponseObserved = false;

            while (true)
            {
                byte[] responseBytes;

                try
                {
                    responseBytes = await ReadNextResponsePacketBytesAsync(cancellationRequested ? CancellationToken.None : cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!cancellationRequested && cancellationToken.IsCancellationRequested)
                {
                    cancellationRequested = true;

                    if (pendingResponseObserved && !cancelIssued)
                    {
                        await WriteCancelRequestAsync(requestHeader.MessageId).ConfigureAwait(false);
                        cancelIssued = true;
                    }

                    continue;
                }

                OpenCifsClientSession session = _GetSession();
                Smb2CompoundPacket responsePacket = Smb2CompoundPacket.ReadFrom(responseBytes);
                session.ValidateResponsePacket(responsePacket, responseBytes);

                if (responsePacket.Entries.Count != 1)
                {
                    throw new OpenCifsClientProtocolException("The managed direct-TCP client connection expects one SMB2 response per request in the current slice.");
                }

                Smb2CompoundPacketEntry responseEntry = responsePacket.Entries[0];

                if (responseEntry.Header.Command != requestHeader.Command)
                {
                    throw new OpenCifsClientProtocolException("The server response command does not match the request command.");
                }

                session.ApplyResponseHeader(responseEntry.Header);

                if (responseEntry.Header.Status == NtStatus.Pending)
                {
                    if ((responseEntry.Header.Flags & Smb2HeaderFlags.AsyncCommand) == 0)
                    {
                        throw new OpenCifsClientProtocolException("The managed direct-TCP client connection does not support synchronous STATUS_PENDING SMB2 responses.");
                    }

                    pendingResponseObserved = true;

                    if (cancellationRequested && !cancelIssued)
                    {
                        await WriteCancelRequestAsync(requestHeader.MessageId).ConfigureAwait(false);
                        cancelIssued = true;
                    }

                    continue;
                }

                return new OpenCifsClientChangeNotifyRequestResponse(
                    responseEntry.Header,
                    OpenCifsClientResponseDecoder.GetResponsePayloadBytes(responseEntry),
                    cancelIssued && responseEntry.Header.Status == NtStatus.Cancelled);
            }
        }

        public async Task<byte[]> ReadNextResponsePacketBytesAsync(CancellationToken cancellationToken)
        {
            FramedPipeConnection connection = GetConnectedConnection();
            byte[] responseBytes = await connection.ReadAsync(cancellationToken).ConfigureAwait(false);
            return _GetSession().UnwrapResponsePacket(responseBytes);
        }

        private async Task WriteCancelRequestAsync(ulong pendingMessageId)
        {
            OpenCifsClientSession session = _GetSession();
            Smb2Header cancelHeader = session.CreateCancelRequestHeader(pendingMessageId);
            Smb2CancelRequest cancelRequest = session.CreateCancelRequest();
            Smb2CompoundPacket cancelPacket = new Smb2CompoundPacket(new Smb2CompoundPacketEntry[]
            {
                new Smb2CompoundPacketEntry(cancelHeader, cancelRequest.ToByteArray())
            });
            await WriteRequestPacketAsync(cancelPacket, CancellationToken.None).ConfigureAwait(false);
        }

        private async Task WriteRequestPacketAsync(Smb2CompoundPacket requestPacket, CancellationToken cancellationToken)
        {
            FramedPipeConnection connection = GetConnectedConnection();
            byte[] packetBytes = _GetSession().FinalizeRequestPacket(requestPacket);
            await connection.WriteAsync(packetBytes, cancellationToken).ConfigureAwait(false);
        }

        private FramedPipeConnection GetConnectedConnection()
        {
            FramedPipeConnection? connection = _GetConnection();

            if (connection == null)
            {
                throw new OpenCifsClientStateException("The client connection is not connected.");
            }

            return connection;
        }

        private readonly Func<FramedPipeConnection?> _GetConnection;
        private readonly Func<OpenCifsClientSession> _GetSession;
    }
}
