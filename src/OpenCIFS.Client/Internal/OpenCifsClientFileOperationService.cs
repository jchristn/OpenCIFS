namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;
    using FileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal sealed class OpenCifsClientFileOperationService
    {
        public OpenCifsClientFileOperationService(
            Func<OpenCifsClientSession> getSession,
            Action<OpenCifsClientOpenHandle> validateOpenHandle,
            Action<OpenCifsClientOpenHandle, string> validateFileOpenHandle,
            Action<OpenCifsClientOpenHandle, string> validateDirectoryOpenHandle,
            Action<OpenCifsClientOpenHandle> removeOpenHandle,
            Func<string, string> normalizeRelativePath,
            Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> sendSingleRequestAsync,
            Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientChangeNotifyRequestResponse>> sendChangeNotifyRequestAsync,
            Func<ushort, CancellationToken, Task> ensureCreditsAsync)
        {
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
            _ValidateOpenHandle = validateOpenHandle ?? throw new ArgumentNullException(nameof(validateOpenHandle), "ValidateOpenHandle cannot be null.");
            _ValidateFileOpenHandle = validateFileOpenHandle ?? throw new ArgumentNullException(nameof(validateFileOpenHandle), "ValidateFileOpenHandle cannot be null.");
            _ValidateDirectoryOpenHandle = validateDirectoryOpenHandle ?? throw new ArgumentNullException(nameof(validateDirectoryOpenHandle), "ValidateDirectoryOpenHandle cannot be null.");
            _RemoveOpenHandle = removeOpenHandle ?? throw new ArgumentNullException(nameof(removeOpenHandle), "RemoveOpenHandle cannot be null.");
            _NormalizeRelativePath = normalizeRelativePath ?? throw new ArgumentNullException(nameof(normalizeRelativePath), "NormalizeRelativePath cannot be null.");
            _SendSingleRequestAsync = sendSingleRequestAsync ?? throw new ArgumentNullException(nameof(sendSingleRequestAsync), "SendSingleRequestAsync cannot be null.");
            _SendChangeNotifyRequestAsync = sendChangeNotifyRequestAsync ?? throw new ArgumentNullException(nameof(sendChangeNotifyRequestAsync), "SendChangeNotifyRequestAsync cannot be null.");
            _EnsureCreditsAsync = ensureCreditsAsync ?? throw new ArgumentNullException(nameof(ensureCreditsAsync), "EnsureCreditsAsync cannot be null.");
        }

        public async Task<byte[]> ReadAsync(
            OpenCifsClientOpenHandle openHandle,
            uint length,
            ulong offset,
            uint minimumCount,
            CancellationToken cancellationToken)
        {
            _ValidateFileOpenHandle(openHandle, "SMB2 read");
            OpenCifsClientSession session = _GetSession();
            ushort requiredCredits = session.GetRequiredReadWriteCredits(length);
            ushort creditCharge = session.GetReadWriteCreditCharge(length);
            await _EnsureCreditsAsync(requiredCredits, cancellationToken).ConfigureAwait(false);
            Smb2ReadRequest request = session.CreateReadRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, length, offset, minimumCount);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.Read,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken,
                requiredCredits,
                creditCharge).ConfigureAwait(false);
            return session.ApplyReadResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2ReadResponse.ReadFrom));
        }

        public async Task<uint> WriteAsync(OpenCifsClientOpenHandle openHandle, byte[] data, ulong offset, CancellationToken cancellationToken)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            _ValidateFileOpenHandle(openHandle, "SMB2 write");
            OpenCifsClientSession session = _GetSession();
            ushort requiredCredits = session.GetRequiredReadWriteCredits(checked((uint)data.Length));
            ushort creditCharge = session.GetReadWriteCreditCharge(checked((uint)data.Length));
            await _EnsureCreditsAsync(requiredCredits, cancellationToken).ConfigureAwait(false);
            Smb2WriteRequest request = session.CreateWriteRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, data, offset);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.Write,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken,
                requiredCredits,
                creditCharge).ConfigureAwait(false);
            return session.ApplyWriteResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2WriteResponse.ReadFrom));
        }

        public async Task FlushAsync(OpenCifsClientOpenHandle openHandle, CancellationToken cancellationToken)
        {
            _ValidateFileOpenHandle(openHandle, "SMB2 flush");
            OpenCifsClientSession session = _GetSession();
            Smb2FlushRequest request = session.CreateFlushRequest(openHandle.PersistentFileId, openHandle.VolatileFileId);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.Flush,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            session.ApplyFlushResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2FlushResponse.ReadFrom));
        }

        public async Task LockAsync(OpenCifsClientOpenHandle openHandle, Smb2LockElement[] locks, CancellationToken cancellationToken)
        {
            _ValidateFileOpenHandle(openHandle, "SMB2 lock");

            if (locks == null)
            {
                throw new ArgumentNullException(nameof(locks), "Locks cannot be null.");
            }

            OpenCifsClientSession session = _GetSession();
            Smb2LockRequest request = session.CreateLockRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, locks);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.Lock,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            session.ApplyLockResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2LockResponse.ReadFrom));
        }

        public async Task<byte[]> QueryInfoAsync(
            OpenCifsClientOpenHandle openHandle,
            FileInformationClass informationClass,
            uint outputBufferLength,
            CancellationToken cancellationToken)
        {
            _ValidateOpenHandle(openHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2QueryInfoRequest request = session.CreateQueryInfoRequest(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                informationClass,
                outputBufferLength);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.QueryInfo,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            return session.ApplyQueryInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2QueryInfoResponse.ReadFrom));
        }

        public async Task<byte[]> QueryDirectoryAsync(
            OpenCifsClientOpenHandle openHandle,
            FileInformationClass informationClass,
            uint outputBufferLength,
            string? fileNamePattern,
            Smb2QueryDirectoryFlags flags,
            CancellationToken cancellationToken)
        {
            _ValidateDirectoryOpenHandle(openHandle, "SMB2 query directory");
            OpenCifsClientSession session = _GetSession();
            Smb2QueryDirectoryRequest request = session.CreateQueryDirectoryRequest(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                informationClass,
                outputBufferLength,
                string.IsNullOrWhiteSpace(fileNamePattern) ? "*" : fileNamePattern,
                flags);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.QueryDirectory,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            return session.ApplyQueryDirectoryResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2QueryDirectoryResponse.ReadFrom));
        }

        public async Task<FileNotifyInformation[]> ChangeNotifyAsync(
            OpenCifsClientOpenHandle openHandle,
            FileNotifyChangeFilter completionFilter,
            bool watchTree,
            uint outputBufferLength,
            CancellationToken cancellationToken)
        {
            _ValidateDirectoryOpenHandle(openHandle, "SMB2 change notify");
            OpenCifsClientSession session = _GetSession();
            Smb2ChangeNotifyRequest request = session.CreateChangeNotifyRequest(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                completionFilter,
                watchTree,
                outputBufferLength);
            Smb2Header requestHeader = session.CreateRequestHeader(Smb2Command.ChangeNotify, openHandle.TreeId, sessionId: session.SessionId!.Value);
            OpenCifsClientChangeNotifyRequestResponse responseEnvelope = await _SendChangeNotifyRequestAsync(
                requestHeader,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);

            if (responseEnvelope.CancelledByClient)
            {
                throw new OperationCanceledException("The SMB2 CHANGE_NOTIFY request was cancelled.", cancellationToken);
            }

            return session.ApplyChangeNotifyResult(
                request,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2ChangeNotifyResponse.ReadFrom));
        }

        public async Task SetBasicInfoAsync(OpenCifsClientOpenHandle openHandle, FileBasicInformation information, CancellationToken cancellationToken)
        {
            if (information == null)
            {
                throw new ArgumentNullException(nameof(information), "Information cannot be null.");
            }

            _ValidateOpenHandle(openHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2SetInfoRequest request = session.CreateSetBasicInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, information);
            await ApplySetInfoAsync(openHandle, request, cancellationToken).ConfigureAwait(false);
        }

        public async Task SetEndOfFileAsync(OpenCifsClientOpenHandle openHandle, ulong endOfFile, CancellationToken cancellationToken)
        {
            _ValidateFileOpenHandle(openHandle, "SMB2 set end-of-file");
            OpenCifsClientSession session = _GetSession();
            Smb2SetInfoRequest request = session.CreateSetEndOfFileInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, endOfFile);
            await ApplySetInfoAsync(openHandle, request, cancellationToken).ConfigureAwait(false);
        }

        public async Task SetAllocationSizeAsync(OpenCifsClientOpenHandle openHandle, ulong allocationSize, CancellationToken cancellationToken)
        {
            _ValidateFileOpenHandle(openHandle, "SMB2 set allocation size");
            OpenCifsClientSession session = _GetSession();
            Smb2SetInfoRequest request = session.CreateSetAllocationInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, allocationSize);
            await ApplySetInfoAsync(openHandle, request, cancellationToken).ConfigureAwait(false);
        }

        public async Task SetDeletePendingAsync(OpenCifsClientOpenHandle openHandle, bool deletePending, CancellationToken cancellationToken)
        {
            _ValidateOpenHandle(openHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2SetInfoRequest request = session.CreateSetDispositionInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, deletePending);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.SetInfo,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            session.ApplySetDispositionInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2SetInfoResponse.ReadFrom),
                deletePending);
            openHandle.SetDeletePending(deletePending);
        }

        public async Task SetRenameAsync(
            OpenCifsClientOpenHandle openHandle,
            string path,
            bool replaceIfExists,
            CancellationToken cancellationToken)
        {
            _ValidateOpenHandle(openHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2SetInfoRequest request = session.CreateSetRenameInfoRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, path, replaceIfExists);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.SetInfo,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            session.ApplySetRenameInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2SetInfoResponse.ReadFrom),
                path);
            openHandle.UpdatePath(_NormalizeRelativePath(path));
        }

        public async Task<Smb2CloseResponse> CloseAsync(
            OpenCifsClientOpenHandle openHandle,
            bool postQueryAttributes,
            CancellationToken cancellationToken)
        {
            _ValidateOpenHandle(openHandle);
            OpenCifsClientSession session = _GetSession();
            Smb2CloseRequest request = session.CreateCloseRequest(openHandle.PersistentFileId, openHandle.VolatileFileId, postQueryAttributes);
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.Close,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            Smb2CloseResponse response = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                responseEnvelope.ResponseHeader.Status,
                responseEnvelope.ResponsePayload,
                Smb2CloseResponse.ReadFrom);
            session.ApplyCloseResult(openHandle.PersistentFileId, openHandle.VolatileFileId, responseEnvelope.ResponseHeader.Status, response);
            _RemoveOpenHandle(openHandle);
            return response;
        }

        private async Task ApplySetInfoAsync(OpenCifsClientOpenHandle openHandle, Smb2SetInfoRequest request, CancellationToken cancellationToken)
        {
            OpenCifsClientSession session = _GetSession();
            OpenCifsClientRequestResponse responseEnvelope = await SendRequestAsync(
                Smb2Command.SetInfo,
                openHandle.TreeId,
                request.ToByteArray(),
                cancellationToken).ConfigureAwait(false);
            session.ApplySetInfoResult(
                openHandle.PersistentFileId,
                openHandle.VolatileFileId,
                responseEnvelope.ResponseHeader.Status,
                OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(
                    responseEnvelope.ResponseHeader.Status,
                    responseEnvelope.ResponsePayload,
                    Smb2SetInfoResponse.ReadFrom));
        }

        private async Task<OpenCifsClientRequestResponse> SendRequestAsync(
            Smb2Command command,
            uint treeId,
            byte[] requestPayload,
            CancellationToken cancellationToken,
            ushort creditRequest = 1,
            ushort creditCharge = 0)
        {
            OpenCifsClientSession session = _GetSession();
            Smb2Header requestHeader = session.CreateRequestHeader(
                command,
                treeId,
                creditRequest: creditRequest,
                sessionId: session.SessionId!.Value,
                creditCharge: creditCharge);
            return await _SendSingleRequestAsync(requestHeader, requestPayload, cancellationToken).ConfigureAwait(false);
        }

        private readonly Func<OpenCifsClientSession> _GetSession;
        private readonly Action<OpenCifsClientOpenHandle> _ValidateOpenHandle;
        private readonly Action<OpenCifsClientOpenHandle, string> _ValidateFileOpenHandle;
        private readonly Action<OpenCifsClientOpenHandle, string> _ValidateDirectoryOpenHandle;
        private readonly Action<OpenCifsClientOpenHandle> _RemoveOpenHandle;
        private readonly Func<string, string> _NormalizeRelativePath;
        private readonly Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientRequestResponse>> _SendSingleRequestAsync;
        private readonly Func<Smb2Header, byte[], CancellationToken, Task<OpenCifsClientChangeNotifyRequestResponse>> _SendChangeNotifyRequestAsync;
        private readonly Func<ushort, CancellationToken, Task> _EnsureCreditsAsync;
    }
}
