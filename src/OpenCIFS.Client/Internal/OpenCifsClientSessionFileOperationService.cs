namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientSessionFileOperationService
    {
        private const ulong WildcardIoctlFileId = UInt64.MaxValue;

        public OpenCifsClientSessionFileOperationService(
            Func<ulong, ulong, ClientOpenRecord> getTrackedOpen,
            Action<ulong, ulong> removeTrackedOpen,
            Func<bool> getIsNegotiated,
            Func<uint> getNegotiatedMaxReadSize,
            Func<uint> getNegotiatedMaxWriteSize,
            Action ensureAuthenticatedSession,
            Func<SmbDialect[]?> getLastOfferedDialects,
            Func<Smb2GlobalCapabilities> getNegotiatedClientCapabilities,
            Func<Smb2SecurityMode> getNegotiatedClientSecurityMode,
            Func<Guid> getClientGuid,
            Func<SmbDialect?> getNegotiatedDialect,
            Func<Guid?> getServerGuid,
            Func<Smb2GlobalCapabilities> getNegotiatedServerCapabilities,
            Func<Smb2SecurityMode> getNegotiatedServerSecurityMode,
            Action markSecureNegotiateValidated,
            Func<string, string> normalizeOpenPath)
        {
            _GetTrackedOpen = getTrackedOpen ?? throw new ArgumentNullException(nameof(getTrackedOpen), "GetTrackedOpen cannot be null.");
            _RemoveTrackedOpen = removeTrackedOpen ?? throw new ArgumentNullException(nameof(removeTrackedOpen), "RemoveTrackedOpen cannot be null.");
            _GetIsNegotiated = getIsNegotiated ?? throw new ArgumentNullException(nameof(getIsNegotiated), "GetIsNegotiated cannot be null.");
            _GetNegotiatedMaxReadSize = getNegotiatedMaxReadSize ?? throw new ArgumentNullException(nameof(getNegotiatedMaxReadSize), "GetNegotiatedMaxReadSize cannot be null.");
            _GetNegotiatedMaxWriteSize = getNegotiatedMaxWriteSize ?? throw new ArgumentNullException(nameof(getNegotiatedMaxWriteSize), "GetNegotiatedMaxWriteSize cannot be null.");
            _EnsureAuthenticatedSession = ensureAuthenticatedSession ?? throw new ArgumentNullException(nameof(ensureAuthenticatedSession), "EnsureAuthenticatedSession cannot be null.");
            _GetLastOfferedDialects = getLastOfferedDialects ?? throw new ArgumentNullException(nameof(getLastOfferedDialects), "GetLastOfferedDialects cannot be null.");
            _GetNegotiatedClientCapabilities = getNegotiatedClientCapabilities ?? throw new ArgumentNullException(nameof(getNegotiatedClientCapabilities), "GetNegotiatedClientCapabilities cannot be null.");
            _GetNegotiatedClientSecurityMode = getNegotiatedClientSecurityMode ?? throw new ArgumentNullException(nameof(getNegotiatedClientSecurityMode), "GetNegotiatedClientSecurityMode cannot be null.");
            _GetClientGuid = getClientGuid ?? throw new ArgumentNullException(nameof(getClientGuid), "GetClientGuid cannot be null.");
            _GetNegotiatedDialect = getNegotiatedDialect ?? throw new ArgumentNullException(nameof(getNegotiatedDialect), "GetNegotiatedDialect cannot be null.");
            _GetServerGuid = getServerGuid ?? throw new ArgumentNullException(nameof(getServerGuid), "GetServerGuid cannot be null.");
            _GetNegotiatedServerCapabilities = getNegotiatedServerCapabilities ?? throw new ArgumentNullException(nameof(getNegotiatedServerCapabilities), "GetNegotiatedServerCapabilities cannot be null.");
            _GetNegotiatedServerSecurityMode = getNegotiatedServerSecurityMode ?? throw new ArgumentNullException(nameof(getNegotiatedServerSecurityMode), "GetNegotiatedServerSecurityMode cannot be null.");
            _MarkSecureNegotiateValidated = markSecureNegotiateValidated ?? throw new ArgumentNullException(nameof(markSecureNegotiateValidated), "MarkSecureNegotiateValidated cannot be null.");
            _NormalizeOpenPath = normalizeOpenPath ?? throw new ArgumentNullException(nameof(normalizeOpenPath), "NormalizeOpenPath cannot be null.");
        }

        public Smb2ReadRequest CreateReadRequest(ulong persistentFileId, ulong volatileFileId, uint length, ulong offset, uint minimumCount = 0)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (_GetIsNegotiated() && length > _GetNegotiatedMaxReadSize())
            {
                throw new ArgumentOutOfRangeException(nameof(length), "The requested SMB2 read length exceeds the negotiated maximum read size.");
            }

            Smb2ReadRequest request = new Smb2ReadRequest
            {
                Length = length,
                Offset = offset,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                MinimumCount = minimumCount,
                Channel = 0,
                RemainingBytes = 0,
                ReadChannelInfo = Array.Empty<byte>()
            };

            try
            {
                Smb2ReadRequestValidator.Validate(request);
            }
            catch (ProtocolValidationException exception)
            {
                throw new OpenCifsClientProtocolException(exception.Message, exception.ParamName, exception);
            }

            return request;
        }

        public byte[] ApplyReadResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2ReadResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status == NtStatus.EndOfFile)
            {
                return Array.Empty<byte>();
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Read, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            try
            {
                Smb2ReadResponseValidator.Validate(response);
            }
            catch (ProtocolValidationException exception)
            {
                throw new OpenCifsClientProtocolException(exception.Message, exception.ParamName, exception);
            }

            return response.DataBuffer;
        }

        public Smb2WriteRequest CreateWriteRequest(ulong persistentFileId, ulong volatileFileId, byte[] data, ulong offset)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (_GetIsNegotiated() && data.Length > _GetNegotiatedMaxWriteSize())
            {
                throw new ArgumentOutOfRangeException(nameof(data), "The SMB2 write length exceeds the negotiated maximum write size.");
            }

            Smb2WriteRequest request = new Smb2WriteRequest
            {
                Offset = offset,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                Channel = 0,
                RemainingBytes = 0,
                Flags = Smb2WriteFlags.None,
                DataBuffer = (byte[])data.Clone(),
                WriteChannelInfo = Array.Empty<byte>()
            };

            Smb2WriteRequestValidator.Validate(request);
            return request;
        }

        public uint ApplyWriteResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2WriteResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Write, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2WriteResponseValidator.Validate(response);
            return response.Count;
        }

        public Smb2FlushRequest CreateFlushRequest(ulong persistentFileId, ulong volatileFileId)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2FlushRequest request = new Smb2FlushRequest
            {
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId
            };

            Smb2FlushRequestValidator.Validate(request);
            return request;
        }

        public void ApplyFlushResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2FlushResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Flush, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2FlushResponseValidator.Validate(response);
        }

        public Smb2CloseRequest CreateCloseRequest(ulong persistentFileId, ulong volatileFileId, bool postQueryAttributes = false)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2CloseRequest request = new Smb2CloseRequest
            {
                Flags = postQueryAttributes ? Smb2CloseFlags.PostQueryAttributes : Smb2CloseFlags.None,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId
            };

            Smb2CloseRequestValidator.Validate(request);
            return request;
        }

        public Smb2CloseResponse ApplyCloseResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2CloseResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Close, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2CloseResponseValidator.Validate(response);
            _RemoveTrackedOpen(persistentFileId, volatileFileId);
            return response;
        }

        public Smb2LockRequest CreateLockRequest(ulong persistentFileId, ulong volatileFileId, params Smb2LockElement[] locks)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2LockRequest request = new Smb2LockRequest
            {
                LockSequence = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                Locks = locks ?? throw new ArgumentNullException(nameof(locks), "Locks cannot be null.")
            };

            Smb2LockRequestValidator.Validate(request);
            return request;
        }

        public void ApplyLockResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2LockResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Lock, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2LockResponseValidator.Validate(response);
        }

        public Smb2IoctlRequest CreateIoctlRequest(
            ulong persistentFileId,
            ulong volatileFileId,
            uint ctlCode,
            byte[]? inputBuffer = null,
            uint maxOutputResponse = 4096,
            uint maxInputResponse = 0,
            Smb2IoctlFlags flags = Smb2IoctlFlags.IsFsctl)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            return CreateIoctlRequestCore(
                persistentFileId,
                volatileFileId,
                ctlCode,
                inputBuffer,
                maxOutputResponse,
                maxInputResponse,
                flags);
        }

        public Smb2IoctlRequest CreateConnectionIoctlRequest(
            uint ctlCode,
            byte[]? inputBuffer = null,
            uint maxOutputResponse = 4096,
            uint maxInputResponse = 0,
            Smb2IoctlFlags flags = Smb2IoctlFlags.IsFsctl)
        {
            _EnsureAuthenticatedSession();
            return CreateIoctlRequestCore(
                WildcardIoctlFileId,
                WildcardIoctlFileId,
                ctlCode,
                inputBuffer,
                maxOutputResponse,
                maxInputResponse,
                flags);
        }

        public byte[] ApplyIoctlResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2IoctlResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            return ApplyIoctlResultCore(status, response);
        }

        public byte[] ApplyConnectionIoctlResult(NtStatus status, Smb2IoctlResponse response)
        {
            _EnsureAuthenticatedSession();

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            if (response.PersistentFileId != WildcardIoctlFileId || response.VolatileFileId != WildcardIoctlFileId)
            {
                throw new OpenCifsClientStateException("The SMB2 IOCTL result does not use the wildcard file identifier pair expected for a connection-scoped request.");
            }

            return ApplyIoctlResultCore(status, response);
        }

        public Smb2IoctlRequest CreateValidateNegotiateInfoRequest(uint maxOutputResponse = 24)
        {
            SmbDialect[]? lastOfferedDialects = _GetLastOfferedDialects();

            if (lastOfferedDialects == null || lastOfferedDialects.Length == 0)
            {
                throw new OpenCifsClientStateException("A negotiate request must be created before secure-negotiate validation can be requested.");
            }

            ValidateNegotiateInfoRequest request = new ValidateNegotiateInfoRequest
            {
                Capabilities = _GetNegotiatedClientCapabilities(),
                ClientGuid = _GetClientGuid(),
                SecurityMode = _GetNegotiatedClientSecurityMode(),
                Dialects = (SmbDialect[])lastOfferedDialects.Clone()
            };

            return CreateConnectionIoctlRequest(
                (uint)FsctlCode.ValidateNegotiateInfo,
                request.ToByteArray(),
                maxOutputResponse: maxOutputResponse,
                maxInputResponse: 0,
                flags: Smb2IoctlFlags.IsFsctl);
        }

        public ValidateNegotiateInfoResponse ApplyValidateNegotiateInfoResult(NtStatus status, Smb2IoctlResponse response)
        {
            if (!_GetNegotiatedDialect().HasValue || !_GetServerGuid().HasValue)
            {
                throw new OpenCifsClientStateException("A negotiated SMB session is required before secure-negotiate validation responses can be applied.");
            }

            byte[] outputBuffer = ApplyConnectionIoctlResult(status, response);

            if (response.CtlCode != (uint)FsctlCode.ValidateNegotiateInfo)
            {
                throw new OpenCifsClientProtocolException("The server IOCTL result does not contain an FSCTL_VALIDATE_NEGOTIATE_INFO response.");
            }

            ValidateNegotiateInfoResponse validateResponse;

            try
            {
                validateResponse = ValidateNegotiateInfoResponse.ReadFrom(outputBuffer);
            }
            catch (ProtocolEncodingException exception)
            {
                throw new OpenCifsClientProtocolException("The server FSCTL_VALIDATE_NEGOTIATE_INFO payload is malformed.", exception);
            }

            if (validateResponse.Capabilities != _GetNegotiatedServerCapabilities())
            {
                throw new OpenCifsClientProtocolException("The server FSCTL_VALIDATE_NEGOTIATE_INFO response capabilities do not match the negotiated SMB state.");
            }

            if (validateResponse.ServerGuid != _GetServerGuid()!.Value)
            {
                throw new OpenCifsClientProtocolException("The server FSCTL_VALIDATE_NEGOTIATE_INFO response GUID does not match the negotiated SMB state.");
            }

            if (validateResponse.SecurityMode != _GetNegotiatedServerSecurityMode())
            {
                throw new OpenCifsClientProtocolException("The server FSCTL_VALIDATE_NEGOTIATE_INFO response security mode does not match the negotiated SMB state.");
            }

            if (validateResponse.Dialect != _GetNegotiatedDialect()!.Value)
            {
                throw new OpenCifsClientProtocolException("The server FSCTL_VALIDATE_NEGOTIATE_INFO response dialect does not match the negotiated SMB state.");
            }

            _MarkSecureNegotiateValidated();
            return validateResponse;
        }

        public Smb2IoctlRequest CreateEnumerateSnapshotsRequest(ulong persistentFileId, ulong volatileFileId, uint maxOutputResponse = 4096)
        {
            return CreateIoctlRequest(
                persistentFileId,
                volatileFileId,
                (uint)FsctlCode.SrvEnumerateSnapshots,
                inputBuffer: Array.Empty<byte>(),
                maxOutputResponse: maxOutputResponse,
                maxInputResponse: 0,
                flags: Smb2IoctlFlags.IsFsctl);
        }

        public SrvSnapshotArray ApplyEnumerateSnapshotsResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2IoctlResponse response)
        {
            byte[] outputBuffer = ApplyIoctlResult(persistentFileId, volatileFileId, status, response);

            if (response.CtlCode != (uint)FsctlCode.SrvEnumerateSnapshots)
            {
                throw new OpenCifsClientStateException("The server IOCTL result does not contain an FSCTL_SRV_ENUMERATE_SNAPSHOTS response.");
            }

            return SrvSnapshotArray.ReadFrom(outputBuffer);
        }

        public Smb2QueryInfoRequest CreateQueryInfoRequest(ulong persistentFileId, ulong volatileFileId, FileInformationClass informationClass, uint outputBufferLength = 4096)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2QueryInfoRequest request = new Smb2QueryInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = informationClass,
                OutputBufferLength = outputBufferLength,
                AdditionalInformation = 0,
                Flags = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                InputBuffer = Array.Empty<byte>()
            };

            Smb2QueryInfoRequestValidator.Validate(request);
            return request;
        }

        public byte[] ApplyQueryInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2QueryInfoResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.QueryInfo, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2QueryInfoResponseValidator.Validate(response);
            return response.OutputBuffer;
        }

        public Smb2QueryDirectoryRequest CreateQueryDirectoryRequest(
            ulong persistentFileId,
            ulong volatileFileId,
            FileInformationClass informationClass,
            uint outputBufferLength = 4096,
            string? fileNamePattern = null,
            Smb2QueryDirectoryFlags flags = Smb2QueryDirectoryFlags.None)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2QueryDirectoryRequest request = new Smb2QueryDirectoryRequest
            {
                FileInfoClass = informationClass,
                Flags = flags,
                FileIndex = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                OutputBufferLength = outputBufferLength,
                FileNamePattern = fileNamePattern ?? string.Empty
            };

            Smb2QueryDirectoryRequestValidator.Validate(request);
            return request;
        }

        public byte[] ApplyQueryDirectoryResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2QueryDirectoryResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status == NtStatus.NoMoreFiles || status == NtStatus.NoSuchFile)
            {
                return Array.Empty<byte>();
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.QueryDirectory, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2QueryDirectoryResponseValidator.Validate(response);
            return response.OutputBuffer;
        }

        public Smb2ChangeNotifyRequest CreateChangeNotifyRequest(
            ulong persistentFileId,
            ulong volatileFileId,
            FileNotifyChangeFilter completionFilter,
            bool watchTree = false,
            uint outputBufferLength = 4096)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2ChangeNotifyRequest request = new Smb2ChangeNotifyRequest
            {
                Flags = watchTree ? Smb2ChangeNotifyFlags.WatchTree : Smb2ChangeNotifyFlags.None,
                OutputBufferLength = outputBufferLength,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                CompletionFilter = completionFilter
            };

            Smb2ChangeNotifyRequestValidator.Validate(request);
            return request;
        }

        public FileNotifyInformation[] ApplyChangeNotifyResult(Smb2ChangeNotifyRequest request, NtStatus status, Smb2ChangeNotifyResponse response)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request), "Request cannot be null.");
            }

            _GetTrackedOpen(request.PersistentFileId, request.VolatileFileId);

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2ChangeNotifyRequestValidator.Validate(request);
            Smb2ChangeNotifyResponseValidator.Validate(response);

            if (status == NtStatus.NotifyEnumDir)
            {
                if (response.OutputBuffer.Length != 0)
                {
                    throw new OpenCifsClientProtocolException("STATUS_NOTIFY_ENUM_DIR responses must not carry FILE_NOTIFY_INFORMATION entries in the current slice.", nameof(response));
                }

                return Array.Empty<FileNotifyInformation>();
            }

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.ChangeNotify, status);
            }

            if (request.OutputBufferLength != 0 && response.OutputBuffer.Length > request.OutputBufferLength)
            {
                throw new OpenCifsClientProtocolException("The CHANGE_NOTIFY response output buffer exceeds the request limit.", nameof(response));
            }

            if (response.OutputBuffer.Length == 0)
            {
                throw new OpenCifsClientProtocolException("Successful CHANGE_NOTIFY responses must carry at least one FILE_NOTIFY_INFORMATION entry.", nameof(response));
            }

            FileNotifyInformation[] entries = FileNotifyInformation.DecodeEntries(response.OutputBuffer);
            bool watchTree = (request.Flags & Smb2ChangeNotifyFlags.WatchTree) != 0;

            for (int index = 0; index < entries.Length; index++)
            {
                string fileName = entries[index].FileName;

                if (fileName.Length == 0)
                {
                    throw new OpenCifsClientProtocolException("CHANGE_NOTIFY response entries must carry a relative path.", nameof(response));
                }

                if (fileName[0] == '\\' || fileName[0] == '/')
                {
                    throw new OpenCifsClientProtocolException("CHANGE_NOTIFY response entries must be relative to the watched directory.", nameof(response));
                }

                if (fileName.IndexOf('\"') >= 0)
                {
                    throw new OpenCifsClientProtocolException("CHANGE_NOTIFY response entries must not contain quote characters.", nameof(response));
                }

                if (!watchTree && (fileName.IndexOf('\\') >= 0 || fileName.IndexOf('/') >= 0))
                {
                    throw new OpenCifsClientProtocolException("Non-recursive CHANGE_NOTIFY responses must not contain nested relative paths.", nameof(response));
                }
            }

            return entries;
        }

        public Smb2SetInfoRequest CreateSetBasicInfoRequest(ulong persistentFileId, ulong volatileFileId, FileBasicInformation information)
        {
            if (information == null)
            {
                throw new ArgumentNullException(nameof(information), "Information cannot be null.");
            }

            return CreateSetInfoRequest(persistentFileId, volatileFileId, FileInformationClass.BasicInformation, information.ToByteArray());
        }

        public Smb2SetInfoRequest CreateSetEndOfFileInfoRequest(ulong persistentFileId, ulong volatileFileId, ulong endOfFile)
        {
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.EndOfFileInformation,
                new FileEndOfFileInformation
                {
                    EndOfFile = endOfFile
                }.ToByteArray());
        }

        public Smb2SetInfoRequest CreateSetAllocationInfoRequest(ulong persistentFileId, ulong volatileFileId, ulong allocationSize)
        {
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.AllocationInformation,
                new FileAllocationInformation
                {
                    AllocationSize = allocationSize
                }.ToByteArray());
        }

        public Smb2SetInfoRequest CreateSetDispositionInfoRequest(ulong persistentFileId, ulong volatileFileId, bool deletePending)
        {
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.DispositionInformation,
                new FileDispositionInformation
                {
                    DeletePending = deletePending
                }.ToByteArray());
        }

        public Smb2SetInfoRequest CreateSetRenameInfoRequest(ulong persistentFileId, ulong volatileFileId, string path, bool replaceIfExists = false)
        {
            string normalizedPath = _NormalizeOpenPath(path);
            return CreateSetInfoRequest(
                persistentFileId,
                volatileFileId,
                FileInformationClass.RenameInformation,
                new FileRenameInformationType2
                {
                    ReplaceIfExists = replaceIfExists,
                    RootDirectory = 0,
                    FileName = normalizedPath
                }.ToByteArray());
        }

        public void ApplySetInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2SetInfoResponse response)
        {
            _GetTrackedOpen(persistentFileId, volatileFileId);

            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.SetInfo, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2SetInfoResponseValidator.Validate(response);
        }

        public void ApplySetDispositionInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2SetInfoResponse response, bool deletePending)
        {
            ClientOpenRecord openRecord = _GetTrackedOpen(persistentFileId, volatileFileId);
            ApplySetInfoResult(persistentFileId, volatileFileId, status, response);
            openRecord.State.SetDeletePending(deletePending);
        }

        public void ApplySetRenameInfoResult(ulong persistentFileId, ulong volatileFileId, NtStatus status, Smb2SetInfoResponse response, string path)
        {
            ClientOpenRecord openRecord = _GetTrackedOpen(persistentFileId, volatileFileId);
            ApplySetInfoResult(persistentFileId, volatileFileId, status, response);
            openRecord.State.UpdatePath(_NormalizeOpenPath(path));
        }

        private Smb2SetInfoRequest CreateSetInfoRequest(ulong persistentFileId, ulong volatileFileId, FileInformationClass informationClass, byte[] buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer), "Buffer cannot be null.");
            }

            _GetTrackedOpen(persistentFileId, volatileFileId);
            Smb2SetInfoRequest request = new Smb2SetInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = informationClass,
                AdditionalInformation = 0,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                Buffer = (byte[])buffer.Clone()
            };

            Smb2SetInfoRequestValidator.Validate(request);
            return request;
        }

        private Smb2IoctlRequest CreateIoctlRequestCore(
            ulong persistentFileId,
            ulong volatileFileId,
            uint ctlCode,
            byte[]? inputBuffer,
            uint maxOutputResponse,
            uint maxInputResponse,
            Smb2IoctlFlags flags)
        {
            Smb2IoctlRequest request = new Smb2IoctlRequest
            {
                CtlCode = ctlCode,
                PersistentFileId = persistentFileId,
                VolatileFileId = volatileFileId,
                MaxInputResponse = maxInputResponse,
                MaxOutputResponse = maxOutputResponse,
                Flags = flags,
                InputBuffer = inputBuffer == null ? Array.Empty<byte>() : (byte[])inputBuffer.Clone()
            };

            Smb2IoctlRequestValidator.Validate(request);
            return request;
        }

        private static byte[] ApplyIoctlResultCore(NtStatus status, Smb2IoctlResponse response)
        {
            if (status != NtStatus.Success)
            {
                throw new OpenCifsStatusException(Smb2Command.Ioctl, status);
            }

            if (response == null)
            {
                throw new ArgumentNullException(nameof(response), "Response cannot be null.");
            }

            Smb2IoctlResponseValidator.Validate(response);
            return response.OutputBuffer;
        }

        private readonly Func<ulong, ulong, ClientOpenRecord> _GetTrackedOpen;
        private readonly Action<ulong, ulong> _RemoveTrackedOpen;
        private readonly Func<bool> _GetIsNegotiated;
        private readonly Func<uint> _GetNegotiatedMaxReadSize;
        private readonly Func<uint> _GetNegotiatedMaxWriteSize;
        private readonly Action _EnsureAuthenticatedSession;
        private readonly Func<SmbDialect[]?> _GetLastOfferedDialects;
        private readonly Func<Smb2GlobalCapabilities> _GetNegotiatedClientCapabilities;
        private readonly Func<Smb2SecurityMode> _GetNegotiatedClientSecurityMode;
        private readonly Func<Guid> _GetClientGuid;
        private readonly Func<SmbDialect?> _GetNegotiatedDialect;
        private readonly Func<Guid?> _GetServerGuid;
        private readonly Func<Smb2GlobalCapabilities> _GetNegotiatedServerCapabilities;
        private readonly Func<Smb2SecurityMode> _GetNegotiatedServerSecurityMode;
        private readonly Action _MarkSecureNegotiateValidated;
        private readonly Func<string, string> _NormalizeOpenPath;
    }
}
