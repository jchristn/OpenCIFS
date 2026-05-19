namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerRelatedCompoundRequestDispatcher
    {
        private readonly OpenCifsServerHost _OwnerHost;
        private readonly Action<string> _WriteDiagnostic;
        private readonly Action<Smb2Header, uint, string> _ValidateReadWriteCreditCharge;

        public OpenCifsServerRelatedCompoundRequestDispatcher(
            OpenCifsServerHost ownerHost,
            Action<string> writeDiagnostic,
            Action<Smb2Header, uint, string> validateReadWriteCreditCharge)
        {
            _OwnerHost = ownerHost ?? throw new ArgumentNullException(nameof(ownerHost), "OwnerHost cannot be null.");
            _WriteDiagnostic = writeDiagnostic ?? throw new ArgumentNullException(nameof(writeDiagnostic), "WriteDiagnostic cannot be null.");
            _ValidateReadWriteCreditCharge = validateReadWriteCreditCharge ?? throw new ArgumentNullException(nameof(validateReadWriteCreditCharge), "ValidateReadWriteCreditCharge cannot be null.");
        }

        public Smb2CompoundPacket HandleRequestPacket(Smb2CompoundPacket requestPacket)
        {
            List<Smb2CompoundPacketEntry> responseEntries = new List<Smb2CompoundPacketEntry>(requestPacket.Entries.Count);
            RelatedCompoundContext context = new RelatedCompoundContext();

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                responseEntries.Add(HandleRequestEntry(requestPacket.Entries[index], context, isFirstEntry: index == 0));
            }

            return new Smb2CompoundPacket(responseEntries);
        }

        private Smb2CompoundPacketEntry HandleRequestEntry(Smb2CompoundPacketEntry requestEntry, RelatedCompoundContext context, bool isFirstEntry)
        {
            Smb2Header requestHeader = requestEntry.Header;
            byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimRequestPayload(requestHeader.Command, requestEntry.Payload);
            Smb2Header effectiveHeader = OpenCifsServerCompoundDispatchUtilities.CloneHeader(requestHeader);
            Smb2HeaderFlags responseFlags = isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations;

            _WriteDiagnostic(
                "Dispatching related request entry: command=" +
                requestHeader.Command +
                ", messageId=" +
                requestHeader.MessageId +
                ", sessionId=" +
                requestHeader.SessionId +
                ", treeId=" +
                requestHeader.TreeId +
                ", flags=" +
                requestHeader.Flags +
                ", firstEntry=" +
                isFirstEntry +
                ".");

            if (!isFirstEntry)
            {
                effectiveHeader.Flags = (requestHeader.Flags & Smb2HeaderFlags.Signed) | Smb2HeaderFlags.RelatedOperations;

                if (OpenCifsServerCompoundDispatchUtilities.CommandRequiresSessionId(requestHeader.Command))
                {
                    if (!context.HasSessionId)
                    {
                        return CreateRelatedErrorResponseEntry(effectiveHeader, requestHeader.Command, NtStatus.InvalidParameter, context, responseFlags);
                    }

                    effectiveHeader.SessionId = context.SessionId;
                }

                if (OpenCifsServerCompoundDispatchUtilities.CommandRequiresTreeId(requestHeader.Command))
                {
                    if (!context.HasTreeId)
                    {
                        return CreateRelatedErrorResponseEntry(effectiveHeader, requestHeader.Command, NtStatus.InvalidParameter, context, responseFlags);
                    }

                    effectiveHeader.TreeId = context.TreeId;
                }

                if (OpenCifsServerCompoundDispatchUtilities.CommandRequiresFileId(requestHeader.Command) &&
                    context.PreviousStatus != NtStatus.Success &&
                    (context.HasFileId || context.PreviousCouldGenerateFileId))
                {
                    return CreateRelatedErrorResponseEntry(effectiveHeader, requestHeader.Command, context.PreviousStatus, context, responseFlags);
                }
            }

            switch (requestHeader.Command)
            {
                case Smb2Command.TreeConnect:
                {
                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.TreeConnect,
                        expectedSessionId: effectiveHeader.SessionId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2TreeConnectRequest treeConnectRequest = Smb2TreeConnectRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerTreeConnectResult treeConnectResult = _OwnerHost.HandleTreeConnect(effectiveHeader.SessionId, treeConnectRequest);
                    context.Update(
                        status: treeConnectResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: treeConnectResult.TreeId,
                        hasTreeId: treeConnectResult.TreeId != 0,
                        persistentFileId: 0,
                        volatileFileId: 0,
                        hasFileId: false,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, treeConnectResult.Status, sessionId: effectiveHeader.SessionId, treeId: treeConnectResult.TreeId, additionalFlags: responseFlags),
                        treeConnectResult.Response.ToByteArray());
                }
                case Smb2Command.TreeDisconnect:
                {
                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.TreeDisconnect,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2TreeDisconnectRequest treeDisconnectRequest = Smb2TreeDisconnectRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = _OwnerHost.HandleTreeDisconnect(effectiveHeader.SessionId, effectiveHeader.TreeId, treeDisconnectRequest);
                    context.Update(
                        status: treeDisconnectResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: true,
                        persistentFileId: 0,
                        volatileFileId: 0,
                        hasFileId: false,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, treeDisconnectResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        treeDisconnectResult.Response.ToByteArray());
                }
                case Smb2Command.Create:
                {
                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Create,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2CreateRequest createRequest = Smb2CreateRequest.ReadFrom(trimmedPayload);
                    OpenCifsServerOperationResult<Smb2CreateResponse> createResult = _OwnerHost.HandleCreate(effectiveHeader.SessionId, effectiveHeader.TreeId, createRequest);
                    bool hasGeneratedFileId = createResult.Status == NtStatus.Success &&
                        (createResult.Response.PersistentFileId != 0 || createResult.Response.VolatileFileId != 0);
                    context.Update(
                        status: createResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: createResult.Response.PersistentFileId,
                        volatileFileId: createResult.Response.VolatileFileId,
                        hasFileId: hasGeneratedFileId,
                        previousCouldGenerateFileId: true);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, createResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        createResult.Response.ToByteArray());
                }
                case Smb2Command.Write:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Write,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2WriteRequest writeRequest = Smb2WriteRequest.ReadFrom(trimmedPayload);
                    _ValidateReadWriteCreditCharge(effectiveHeader, checked((uint)writeRequest.DataBuffer.Length), nameof(effectiveHeader));
                    writeRequest.PersistentFileId = persistentFileId;
                    writeRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = _OwnerHost.HandleWrite(effectiveHeader.SessionId, effectiveHeader.TreeId, writeRequest);
                    context.Update(
                        status: writeResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, writeResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        writeResult.Response.ToByteArray());
                }
                case Smb2Command.Flush:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Flush,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2FlushRequest flushRequest = Smb2FlushRequest.ReadFrom(trimmedPayload);
                    flushRequest.PersistentFileId = persistentFileId;
                    flushRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = _OwnerHost.HandleFlush(effectiveHeader.SessionId, effectiveHeader.TreeId, flushRequest);
                    context.Update(
                        status: flushResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, flushResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        flushResult.Response.ToByteArray());
                }
                case Smb2Command.Read:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Read,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2ReadRequest readRequest = Smb2ReadRequest.ReadFrom(trimmedPayload);
                    _ValidateReadWriteCreditCharge(effectiveHeader, readRequest.Length, nameof(effectiveHeader));
                    readRequest.PersistentFileId = persistentFileId;
                    readRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2ReadResponse> readResult = _OwnerHost.HandleRead(effectiveHeader.SessionId, effectiveHeader.TreeId, readRequest);
                    context.Update(
                        status: readResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, readResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        readResult.Response.ToByteArray());
                }
                case Smb2Command.Close:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Close,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2CloseRequest closeRequest = Smb2CloseRequest.ReadFrom(trimmedPayload);
                    closeRequest.PersistentFileId = persistentFileId;
                    closeRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = _OwnerHost.HandleClose(effectiveHeader.SessionId, effectiveHeader.TreeId, closeRequest);
                    context.Update(
                        status: closeResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, closeResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        closeResult.Response.ToByteArray());
                }
                case Smb2Command.Lock:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Lock,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2LockRequest lockRequest = Smb2LockRequest.ReadFrom(trimmedPayload);
                    lockRequest.PersistentFileId = persistentFileId;
                    lockRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2LockResponse> lockResult = _OwnerHost.HandleLock(effectiveHeader.SessionId, effectiveHeader.TreeId, lockRequest);
                    context.Update(
                        status: lockResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, lockResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        lockResult.Response.ToByteArray());
                }
                case Smb2Command.QueryInfo:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.QueryInfo,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2QueryInfoRequest queryInfoRequest = Smb2QueryInfoRequest.ReadFrom(trimmedPayload);
                    queryInfoRequest.PersistentFileId = persistentFileId;
                    queryInfoRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2QueryInfoResponse> queryInfoResult = _OwnerHost.HandleQueryInfo(effectiveHeader.SessionId, effectiveHeader.TreeId, queryInfoRequest);
                    context.Update(
                        status: queryInfoResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, queryInfoResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        queryInfoResult.Response.ToByteArray());
                }
                case Smb2Command.SetInfo:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.SetInfo,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2SetInfoRequest setInfoRequest = Smb2SetInfoRequest.ReadFrom(trimmedPayload);
                    setInfoRequest.PersistentFileId = persistentFileId;
                    setInfoRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2SetInfoResponse> setInfoResult = _OwnerHost.HandleSetInfo(effectiveHeader.SessionId, effectiveHeader.TreeId, setInfoRequest);
                    context.Update(
                        status: setInfoResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, setInfoResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        setInfoResult.Response.ToByteArray());
                }
                case Smb2Command.QueryDirectory:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.QueryDirectory,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2QueryDirectoryRequest queryDirectoryRequest = Smb2QueryDirectoryRequest.ReadFrom(trimmedPayload);
                    queryDirectoryRequest.PersistentFileId = persistentFileId;
                    queryDirectoryRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> queryDirectoryResult = _OwnerHost.HandleQueryDirectory(effectiveHeader.SessionId, effectiveHeader.TreeId, queryDirectoryRequest);
                    context.Update(
                        status: queryDirectoryResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, queryDirectoryResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        queryDirectoryResult.Response.ToByteArray());
                }
                case Smb2Command.Ioctl:
                {
                    if (!PrepareRelatedFileId(effectiveHeader, requestHeader.Command, context, out ulong persistentFileId, out ulong volatileFileId, out Smb2CompoundPacketEntry errorEntry, responseFlags))
                    {
                        return errorEntry;
                    }

                    _OwnerHost.ValidateAndAcceptRequestHeader(
                        effectiveHeader,
                        Smb2Command.Ioctl,
                        expectedSessionId: effectiveHeader.SessionId,
                        expectedTreeId: effectiveHeader.TreeId,
                        allowedRequestFlags: isFirstEntry ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);
                    Smb2IoctlRequest ioctlRequest = Smb2IoctlRequest.ReadFrom(trimmedPayload);

                    if (OpenCifsServerIoctlOperationService.IsWildcardFileId(ioctlRequest.PersistentFileId, ioctlRequest.VolatileFileId))
                    {
                        Smb2IoctlResponse invalidIoctlResponse = OpenCifsServerIoctlOperationService.CreateResponse(
                            ioctlRequest.CtlCode,
                            persistentFileId,
                            volatileFileId,
                            Array.Empty<byte>());
                        context.Update(
                            status: NtStatus.InvalidParameter,
                            sessionId: effectiveHeader.SessionId,
                            hasSessionId: effectiveHeader.SessionId != 0,
                            treeId: effectiveHeader.TreeId,
                            hasTreeId: effectiveHeader.TreeId != 0,
                            persistentFileId: persistentFileId,
                            volatileFileId: volatileFileId,
                            hasFileId: true,
                            previousCouldGenerateFileId: false);
                        return new Smb2CompoundPacketEntry(
                            _OwnerHost.CreateResponseHeader(effectiveHeader, NtStatus.InvalidParameter, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                            invalidIoctlResponse.ToByteArray());
                    }

                    ioctlRequest.PersistentFileId = persistentFileId;
                    ioctlRequest.VolatileFileId = volatileFileId;
                    OpenCifsServerOperationResult<Smb2IoctlResponse> ioctlResult = _OwnerHost.HandleIoctl(effectiveHeader.SessionId, effectiveHeader.TreeId, ioctlRequest);
                    context.Update(
                        status: ioctlResult.Status,
                        sessionId: effectiveHeader.SessionId,
                        hasSessionId: effectiveHeader.SessionId != 0,
                        treeId: effectiveHeader.TreeId,
                        hasTreeId: effectiveHeader.TreeId != 0,
                        persistentFileId: persistentFileId,
                        volatileFileId: volatileFileId,
                        hasFileId: true,
                        previousCouldGenerateFileId: false);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(effectiveHeader, ioctlResult.Status, sessionId: effectiveHeader.SessionId, treeId: effectiveHeader.TreeId, additionalFlags: responseFlags),
                        ioctlResult.Response.ToByteArray());
                }
                default:
                    throw new ProtocolValidationException("Related SMB2 compound request chains are only implemented for the current synchronous tree, file, metadata, locking, and open-scoped IOCTL surface.", nameof(requestEntry));
            }
        }

        private bool PrepareRelatedFileId(
            Smb2Header effectiveHeader,
            Smb2Command command,
            RelatedCompoundContext context,
            out ulong persistentFileId,
            out ulong volatileFileId,
            out Smb2CompoundPacketEntry errorEntry,
            Smb2HeaderFlags responseFlags)
        {
            if (!context.HasFileId)
            {
                NtStatus status = context.PreviousStatus != NtStatus.Success && (context.HasFileId || context.PreviousCouldGenerateFileId)
                    ? context.PreviousStatus
                    : NtStatus.InvalidHandle;
                errorEntry = CreateRelatedErrorResponseEntry(effectiveHeader, command, status, context, responseFlags);
                persistentFileId = 0;
                volatileFileId = 0;
                return false;
            }

            persistentFileId = context.PersistentFileId;
            volatileFileId = context.VolatileFileId;
            errorEntry = null!;
            return true;
        }

        private Smb2CompoundPacketEntry CreateRelatedErrorResponseEntry(
            Smb2Header effectiveHeader,
            Smb2Command command,
            NtStatus status,
            RelatedCompoundContext context,
            Smb2HeaderFlags responseFlags)
        {
            _OwnerHost.ValidateAndAcceptRequestHeader(
                effectiveHeader,
                command,
                expectedSessionId: effectiveHeader.SessionId,
                expectedTreeId: effectiveHeader.TreeId,
                allowedRequestFlags: responseFlags == Smb2HeaderFlags.None ? Smb2HeaderFlags.None : Smb2HeaderFlags.RelatedOperations);

            byte[] payload = OpenCifsServerDefaultResponsePayloadFactory.CreateDefaultResponsePayload(command);
            return new Smb2CompoundPacketEntry(
                _OwnerHost.CreateResponseHeader(
                    effectiveHeader,
                    status,
                    sessionId: effectiveHeader.SessionId != 0 ? effectiveHeader.SessionId : context.SessionId,
                    treeId: effectiveHeader.TreeId != 0 ? effectiveHeader.TreeId : context.TreeId,
                    additionalFlags: responseFlags),
                payload);
        }
    }
}
