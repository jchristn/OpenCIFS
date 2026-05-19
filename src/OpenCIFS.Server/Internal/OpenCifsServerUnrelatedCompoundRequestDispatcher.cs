namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerUnrelatedCompoundRequestDispatcher
    {
        private readonly OpenCifsServerHost _OwnerHost;
        private readonly Action<string> _WriteDiagnostic;
        private readonly Action<Smb2Header, uint, string> _ValidateReadWriteCreditCharge;

        public OpenCifsServerUnrelatedCompoundRequestDispatcher(
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
            ulong compoundedSessionId = 0;

            for (int index = 0; index < requestPacket.Entries.Count; index++)
            {
                Smb2CompoundPacketEntry requestEntry = requestPacket.Entries[index];
                Smb2Header effectiveHeader = OpenCifsServerCompoundDispatchUtilities.CloneHeader(requestEntry.Header);

                _WriteDiagnostic(
                    "Dispatching request entry " +
                    (index + 1).ToString(CultureInfo.InvariantCulture) +
                    "/" +
                    requestPacket.Entries.Count.ToString(CultureInfo.InvariantCulture) +
                    ": command=" +
                    effectiveHeader.Command +
                    ", messageId=" +
                    effectiveHeader.MessageId +
                    ", sessionId=" +
                    effectiveHeader.SessionId +
                    ", treeId=" +
                    effectiveHeader.TreeId +
                    ", flags=" +
                    effectiveHeader.Flags +
                    ".");

                if (compoundedSessionId != 0 &&
                    effectiveHeader.SessionId == 0 &&
                    OpenCifsServerCompoundDispatchUtilities.CommandRequiresSessionId(effectiveHeader.Command))
                {
                    effectiveHeader.SessionId = compoundedSessionId;
                }

                Smb2CompoundPacketEntry responseEntry = HandleRequestEntry(new Smb2CompoundPacketEntry(effectiveHeader, requestEntry.Payload));
                _WriteDiagnostic(
                    "Completed request entry " +
                    (index + 1).ToString(CultureInfo.InvariantCulture) +
                    "/" +
                    requestPacket.Entries.Count.ToString(CultureInfo.InvariantCulture) +
                    ": command=" +
                    effectiveHeader.Command +
                    ", status=" +
                    responseEntry.Header.Status +
                    ", responseSessionId=" +
                    responseEntry.Header.SessionId +
                    ", responseTreeId=" +
                    responseEntry.Header.TreeId +
                    ".");
                responseEntries.Add(responseEntry);

                if (effectiveHeader.Command == Smb2Command.SessionSetup &&
                    responseEntry.Header.Status == NtStatus.Success &&
                    responseEntry.Header.SessionId != 0)
                {
                    compoundedSessionId = responseEntry.Header.SessionId;
                }
            }

            return new Smb2CompoundPacket(responseEntries);
        }

        private Smb2CompoundPacketEntry HandleRequestEntry(Smb2CompoundPacketEntry requestEntry)
        {
            Smb2Header requestHeader = requestEntry.Header;
            byte[] trimmedPayload = Smb2CompoundPayloadHelper.TrimRequestPayload(requestHeader.Command, requestEntry.Payload);

            switch (requestHeader.Command)
            {
                case Smb2Command.Negotiate:
                {
                    Smb2NegotiateRequest negotiateRequest = Smb2NegotiateRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Negotiate);
                    Smb2NegotiateResponse negotiateResponse = _OwnerHost.HandleNegotiate(negotiateRequest);
                    Smb2Header negotiateResponseHeader = _OwnerHost.CreateResponseHeader(requestHeader, NtStatus.Success);
                    byte[] negotiateResponseBody = negotiateResponse.ToByteArray();
                    _OwnerHost.AppendPreauthMessageBytes(requestHeader, trimmedPayload);
                    _OwnerHost.AppendPreauthMessageBytes(negotiateResponseHeader, negotiateResponseBody);
                    return new Smb2CompoundPacketEntry(negotiateResponseHeader, negotiateResponseBody);
                }
                case Smb2Command.SessionSetup:
                {
                    Smb2SessionSetupRequest sessionSetupRequest = Smb2SessionSetupRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.SessionSetup, expectedSessionId: requestHeader.SessionId);
                    _OwnerHost.AppendPreauthMessageBytes(requestHeader, trimmedPayload);
                    OpenCifsServerSessionSetupResult sessionSetupResult = _OwnerHost.HandleSessionSetup(requestHeader.SessionId, sessionSetupRequest);
                    Smb2HeaderFlags sessionSetupResponseFlags = sessionSetupResult.Status == NtStatus.Success
                        ? Smb2HeaderFlags.Signed
                        : Smb2HeaderFlags.None;
                    Smb2Header sessionSetupResponseHeader = _OwnerHost.CreateResponseHeader(
                        requestHeader,
                        sessionSetupResult.Status,
                        sessionId: sessionSetupResult.SessionId,
                        additionalFlags: sessionSetupResponseFlags);
                    byte[] sessionSetupResponseBody = sessionSetupResult.Response.ToByteArray();

                    if (sessionSetupResult.Status == NtStatus.MoreProcessingRequired)
                    {
                        _OwnerHost.AppendPreauthMessageBytes(sessionSetupResponseHeader, sessionSetupResponseBody);
                    }

                    return new Smb2CompoundPacketEntry(sessionSetupResponseHeader, sessionSetupResponseBody);
                }
                case Smb2Command.Logoff:
                {
                    Smb2LogoffRequest logoffRequest = Smb2LogoffRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Logoff, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerOperationResult<Smb2LogoffResponse> logoffResult = _OwnerHost.HandleLogoff(requestHeader.SessionId, logoffRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, logoffResult.Status, sessionId: requestHeader.SessionId),
                        logoffResult.Response.ToByteArray());
                }
                case Smb2Command.Echo:
                {
                    Smb2EchoRequest echoRequest = Smb2EchoRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Echo, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerOperationResult<Smb2EchoResponse> echoResult = _OwnerHost.HandleEcho(requestHeader.SessionId, echoRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, echoResult.Status, sessionId: requestHeader.SessionId),
                        echoResult.Response.ToByteArray());
                }
                case Smb2Command.TreeConnect:
                {
                    Smb2TreeConnectRequest treeConnectRequest = Smb2TreeConnectRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.TreeConnect, expectedSessionId: requestHeader.SessionId);
                    OpenCifsServerTreeConnectResult treeConnectResult = _OwnerHost.HandleTreeConnect(requestHeader.SessionId, treeConnectRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, treeConnectResult.Status, sessionId: requestHeader.SessionId, treeId: treeConnectResult.TreeId),
                        treeConnectResult.Response.ToByteArray());
                }
                case Smb2Command.TreeDisconnect:
                {
                    Smb2TreeDisconnectRequest treeDisconnectRequest = Smb2TreeDisconnectRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.TreeDisconnect, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2TreeDisconnectResponse> treeDisconnectResult = _OwnerHost.HandleTreeDisconnect(requestHeader.SessionId, requestHeader.TreeId, treeDisconnectRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, treeDisconnectResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        treeDisconnectResult.Response.ToByteArray());
                }
                case Smb2Command.Create:
                {
                    Smb2CreateRequest createRequest = Smb2CreateRequest.ReadFrom(trimmedPayload);
                    _WriteDiagnostic(
                        "Create request received for session " +
                        requestHeader.SessionId.ToString(CultureInfo.InvariantCulture) +
                        ", tree " +
                        requestHeader.TreeId.ToString(CultureInfo.InvariantCulture) +
                        ", name '" +
                        createRequest.Name +
                        "', disposition " +
                        createRequest.CreateDisposition +
                        ", options " +
                        createRequest.CreateOptions +
                        ", desired access 0x" +
                        createRequest.DesiredAccess.ToString("X8", CultureInfo.InvariantCulture) +
                        ", share access 0x" +
                        createRequest.ShareAccess.ToString("X8", CultureInfo.InvariantCulture) +
                        ".");
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Create, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2CreateResponse> createResult = _OwnerHost.HandleCreate(requestHeader.SessionId, requestHeader.TreeId, createRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, createResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        createResult.Response.ToByteArray());
                }
                case Smb2Command.Read:
                {
                    Smb2ReadRequest readRequest = Smb2ReadRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Read, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    _ValidateReadWriteCreditCharge(requestHeader, readRequest.Length, nameof(requestHeader));
                    OpenCifsServerOperationResult<Smb2ReadResponse> readResult = _OwnerHost.HandleRead(requestHeader.SessionId, requestHeader.TreeId, readRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, readResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        readResult.Response.ToByteArray());
                }
                case Smb2Command.Write:
                {
                    Smb2WriteRequest writeRequest = Smb2WriteRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Write, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    _ValidateReadWriteCreditCharge(requestHeader, checked((uint)writeRequest.DataBuffer.Length), nameof(requestHeader));
                    OpenCifsServerOperationResult<Smb2WriteResponse> writeResult = _OwnerHost.HandleWrite(requestHeader.SessionId, requestHeader.TreeId, writeRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, writeResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        writeResult.Response.ToByteArray());
                }
                case Smb2Command.Flush:
                {
                    Smb2FlushRequest flushRequest = Smb2FlushRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Flush, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2FlushResponse> flushResult = _OwnerHost.HandleFlush(requestHeader.SessionId, requestHeader.TreeId, flushRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, flushResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        flushResult.Response.ToByteArray());
                }
                case Smb2Command.Close:
                {
                    Smb2CloseRequest closeRequest = Smb2CloseRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Close, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2CloseResponse> closeResult = _OwnerHost.HandleClose(requestHeader.SessionId, requestHeader.TreeId, closeRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, closeResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        closeResult.Response.ToByteArray());
                }
                case Smb2Command.Lock:
                {
                    Smb2LockRequest lockRequest = Smb2LockRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Lock, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2LockResponse> lockResult = _OwnerHost.HandleLock(requestHeader.SessionId, requestHeader.TreeId, lockRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, lockResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        lockResult.Response.ToByteArray());
                }
                case Smb2Command.OplockBreak:
                {
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.OplockBreak, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    ushort breakStructureSize = new LittleEndianReader(trimmedPayload).ReadUInt16();

                    if (breakStructureSize == 24)
                    {
                        Smb2OplockBreakAcknowledgment oplockBreakAcknowledgment = Smb2OplockBreakAcknowledgment.ReadFrom(trimmedPayload);
                        OpenCifsServerOperationResult<Smb2OplockBreakResponse> oplockBreakResult = _OwnerHost.HandleOplockBreakAcknowledgment(requestHeader.SessionId, requestHeader.TreeId, oplockBreakAcknowledgment);
                        return new Smb2CompoundPacketEntry(
                            _OwnerHost.CreateResponseHeader(requestHeader, oplockBreakResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                            oplockBreakResult.Response.ToByteArray());
                    }

                    if (breakStructureSize == 36)
                    {
                        Smb2LeaseBreakAcknowledgment leaseBreakAcknowledgment = Smb2LeaseBreakAcknowledgment.ReadFrom(trimmedPayload);
                        OpenCifsServerOperationResult<Smb2LeaseBreakResponse> leaseBreakResult = _OwnerHost.HandleLeaseBreakAcknowledgment(requestHeader.SessionId, requestHeader.TreeId, leaseBreakAcknowledgment);
                        return new Smb2CompoundPacketEntry(
                            _OwnerHost.CreateResponseHeader(requestHeader, leaseBreakResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                            leaseBreakResult.Response.ToByteArray());
                    }

                    throw new ProtocolValidationException("The SMB2 OPLOCK_BREAK request structure size is not supported in the current SMB 2.1 slice.", nameof(trimmedPayload));
                }
                case Smb2Command.Ioctl:
                {
                    Smb2IoctlRequest ioctlRequest = Smb2IoctlRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.Ioctl, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2IoctlResponse> ioctlResult = _OwnerHost.HandleIoctl(requestHeader.SessionId, requestHeader.TreeId, ioctlRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, ioctlResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        ioctlResult.Response.ToByteArray());
                }
                case Smb2Command.QueryInfo:
                {
                    Smb2QueryInfoRequest queryInfoRequest = Smb2QueryInfoRequest.ReadFrom(trimmedPayload);
                    _WriteDiagnostic(
                        "Query-info request received for session " +
                        requestHeader.SessionId.ToString(CultureInfo.InvariantCulture) +
                        ", tree " +
                        requestHeader.TreeId.ToString(CultureInfo.InvariantCulture) +
                        ", info type " +
                        queryInfoRequest.InfoType +
                        ", file class " +
                        OpenCifsServerQueryInfoService.FormatQueryInfoClass(queryInfoRequest) +
                        ", output length " +
                        queryInfoRequest.OutputBufferLength.ToString(CultureInfo.InvariantCulture) +
                        ", additional information 0x" +
                        queryInfoRequest.AdditionalInformation.ToString("X8", CultureInfo.InvariantCulture) +
                        ", flags 0x" +
                        queryInfoRequest.Flags.ToString("X8", CultureInfo.InvariantCulture) +
                        ".");
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.QueryInfo, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2QueryInfoResponse> queryInfoResult = _OwnerHost.HandleQueryInfo(requestHeader.SessionId, requestHeader.TreeId, queryInfoRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, queryInfoResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        queryInfoResult.Response.ToByteArray());
                }
                case Smb2Command.SetInfo:
                {
                    Smb2SetInfoRequest setInfoRequest = Smb2SetInfoRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.SetInfo, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2SetInfoResponse> setInfoResult = _OwnerHost.HandleSetInfo(requestHeader.SessionId, requestHeader.TreeId, setInfoRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, setInfoResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        setInfoResult.Response.ToByteArray());
                }
                case Smb2Command.QueryDirectory:
                {
                    Smb2QueryDirectoryRequest queryDirectoryRequest = Smb2QueryDirectoryRequest.ReadFrom(trimmedPayload);
                    _OwnerHost.ValidateAndAcceptRequestHeader(requestHeader, Smb2Command.QueryDirectory, expectedSessionId: requestHeader.SessionId, expectedTreeId: requestHeader.TreeId);
                    OpenCifsServerOperationResult<Smb2QueryDirectoryResponse> queryDirectoryResult = _OwnerHost.HandleQueryDirectory(requestHeader.SessionId, requestHeader.TreeId, queryDirectoryRequest);
                    return new Smb2CompoundPacketEntry(
                        _OwnerHost.CreateResponseHeader(requestHeader, queryDirectoryResult.Status, sessionId: requestHeader.SessionId, treeId: requestHeader.TreeId),
                        queryDirectoryResult.Response.ToByteArray());
                }
                default:
                    throw new ProtocolValidationException("The SMB2 command is not supported by the current compounded-request surface.", nameof(requestEntry));
            }
        }
    }
}
