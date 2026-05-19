namespace OpenCIFS.Client
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientCompoundOperationService
    {
        private const ulong RelatedCompoundFileId = UInt64.MaxValue;

        public OpenCifsClientCompoundOperationService(
            Func<OpenCifsClientSession> getSession,
            Action<OpenCifsClientTreeHandle> validateTreeHandle,
            Func<ushort, CancellationToken, Task> ensureCreditsAsync,
            Func<Smb2CompoundPacket, CancellationToken, Task<Smb2CompoundPacket>> sendCompoundRequestAsync,
            Func<Smb2CompoundPacketEntry, byte[]> getResponsePayloadBytes)
        {
            _GetSession = getSession ?? throw new ArgumentNullException(nameof(getSession), "GetSession cannot be null.");
            _ValidateTreeHandle = validateTreeHandle ?? throw new ArgumentNullException(nameof(validateTreeHandle), "ValidateTreeHandle cannot be null.");
            _EnsureCreditsAsync = ensureCreditsAsync ?? throw new ArgumentNullException(nameof(ensureCreditsAsync), "EnsureCreditsAsync cannot be null.");
            _SendCompoundRequestAsync = sendCompoundRequestAsync ?? throw new ArgumentNullException(nameof(sendCompoundRequestAsync), "SendCompoundRequestAsync cannot be null.");
            _GetResponsePayloadBytes = getResponsePayloadBytes ?? throw new ArgumentNullException(nameof(getResponsePayloadBytes), "GetResponsePayloadBytes cannot be null.");
        }

        public async Task<byte[]> CompoundCreateQueryInfoCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            FileInformationClass informationClass,
            uint outputBufferLength,
            uint desiredAccess,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            CancellationToken cancellationToken)
        {
            _ValidateTreeHandle(treeHandle);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            OpenCifsClientSession session = _GetSession();
            await _EnsureCreditsAsync(3, cancellationToken).ConfigureAwait(false);

            Smb2CreateRequest createRequest = session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                FileAttributes.Normal,
                shareAccess,
                createDisposition,
                createOptions);
            Smb2QueryInfoRequest queryRequest = CreateRelatedQueryInfoRequest(informationClass, outputBufferLength);
            Smb2CloseRequest closeRequest = CreateRelatedCloseRequest();
            Smb2Header createHeader = session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            Smb2Header queryHeader = session.CreateRelatedRequestHeader(Smb2Command.QueryInfo, sessionId: session.SessionId!.Value);
            Smb2Header closeHeader = session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: session.SessionId!.Value);
            Smb2CompoundPacket responsePacket = await _SendCompoundRequestAsync(
                new Smb2CompoundPacket(
                    new[]
                    {
                        new Smb2CompoundPacketEntry(createHeader, createRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(queryHeader, queryRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                    }),
                cancellationToken).ConfigureAwait(false);
            AssertCompoundResponseEntryCount(responsePacket, expectedCount: 3);

            Smb2CompoundPacketEntry createEntry = responsePacket.Entries[0];
            Smb2CompoundPacketEntry queryEntry = responsePacket.Entries[1];
            Smb2CompoundPacketEntry closeEntry = responsePacket.Entries[2];
            Smb2CreateResponse createResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(createEntry.Header.Status, _GetResponsePayloadBytes(createEntry), Smb2CreateResponse.ReadFrom);
            Smb2QueryInfoResponse queryResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(queryEntry.Header.Status, _GetResponsePayloadBytes(queryEntry), Smb2QueryInfoResponse.ReadFrom);
            Smb2CloseResponse closeResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(closeEntry.Header.Status, _GetResponsePayloadBytes(closeEntry), Smb2CloseResponse.ReadFrom);
            Exception? compoundFailure = null;
            OpenState? openState = null;
            byte[] outputBuffer = Array.Empty<byte>();

            try
            {
                openState = session.ApplyCreateResult(treeHandle.TreeId, path, createEntry.Header.Status, createResponse);

                try
                {
                    outputBuffer = session.ApplyQueryInfoResult(openState.PersistentFileId, openState.VolatileFileId, queryEntry.Header.Status, queryResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }
            catch (Exception exception)
            {
                compoundFailure ??= exception;
            }

            if (openState != null)
            {
                try
                {
                    session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeEntry.Header.Status, closeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }

            if (compoundFailure != null)
            {
                throw compoundFailure;
            }

            return outputBuffer;
        }

        public async Task<byte[]> CompoundOpenReadCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            uint length,
            ulong offset,
            uint minimumCount,
            uint desiredAccess,
            uint shareAccess,
            Smb2CreateOptions createOptions,
            CancellationToken cancellationToken)
        {
            _ValidateTreeHandle(treeHandle);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            OpenCifsClientSession session = _GetSession();
            ushort readCredits = session.GetRequiredReadWriteCredits(length);
            ushort readCreditCharge = session.GetReadWriteCreditCharge(length);
            await _EnsureCreditsAsync(checked((ushort)(2 + readCredits)), cancellationToken).ConfigureAwait(false);

            Smb2CreateRequest createRequest = session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                FileAttributes.Normal,
                shareAccess,
                Smb2CreateDisposition.Open,
                createOptions);
            Smb2ReadRequest readRequest = CreateRelatedReadRequest(length, offset, minimumCount);
            Smb2CloseRequest closeRequest = CreateRelatedCloseRequest();
            Smb2Header createHeader = session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            Smb2Header readHeader = session.CreateRequestHeader(
                Smb2Command.Read,
                creditRequest: readCredits,
                sessionId: session.SessionId!.Value,
                creditCharge: readCreditCharge);
            readHeader.Flags |= Smb2HeaderFlags.RelatedOperations;
            Smb2HeaderValidator.Validate(readHeader);
            Smb2Header closeHeader = session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: session.SessionId!.Value);
            Smb2CompoundPacket responsePacket = await _SendCompoundRequestAsync(
                new Smb2CompoundPacket(
                    new[]
                    {
                        new Smb2CompoundPacketEntry(createHeader, createRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(readHeader, readRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                    }),
                cancellationToken).ConfigureAwait(false);
            AssertCompoundResponseEntryCount(responsePacket, expectedCount: 3);

            Smb2CompoundPacketEntry createEntry = responsePacket.Entries[0];
            Smb2CompoundPacketEntry readEntry = responsePacket.Entries[1];
            Smb2CompoundPacketEntry closeEntry = responsePacket.Entries[2];
            Smb2CreateResponse createResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(createEntry.Header.Status, _GetResponsePayloadBytes(createEntry), Smb2CreateResponse.ReadFrom);
            Smb2ReadResponse readResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(readEntry.Header.Status, _GetResponsePayloadBytes(readEntry), Smb2ReadResponse.ReadFrom);
            Smb2CloseResponse closeResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(closeEntry.Header.Status, _GetResponsePayloadBytes(closeEntry), Smb2CloseResponse.ReadFrom);
            Exception? compoundFailure = null;
            OpenState? openState = null;
            byte[] data = Array.Empty<byte>();

            try
            {
                openState = session.ApplyCreateResult(treeHandle.TreeId, path, createEntry.Header.Status, createResponse);

                try
                {
                    data = session.ApplyReadResult(openState.PersistentFileId, openState.VolatileFileId, readEntry.Header.Status, readResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }
            catch (Exception exception)
            {
                compoundFailure ??= exception;
            }

            if (openState != null)
            {
                try
                {
                    session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeEntry.Header.Status, closeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }

            if (compoundFailure != null)
            {
                throw compoundFailure;
            }

            return data;
        }

        public async Task<uint> CompoundCreateWriteFlushCloseAsync(
            OpenCifsClientTreeHandle treeHandle,
            string path,
            byte[] data,
            uint desiredAccess,
            FileAttributes fileAttributes,
            uint shareAccess,
            Smb2CreateDisposition createDisposition,
            Smb2CreateOptions createOptions,
            CancellationToken cancellationToken)
        {
            _ValidateTreeHandle(treeHandle);

            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException(nameof(path), "Path cannot be null or whitespace.");
            }

            if (data == null)
            {
                throw new ArgumentNullException(nameof(data), "Data cannot be null.");
            }

            OpenCifsClientSession session = _GetSession();
            ushort writeCredits = session.GetRequiredReadWriteCredits(checked((uint)data.Length));
            ushort writeCreditCharge = session.GetReadWriteCreditCharge(checked((uint)data.Length));
            await _EnsureCreditsAsync(checked((ushort)(3 + writeCredits)), cancellationToken).ConfigureAwait(false);

            Smb2CreateRequest createRequest = session.CreateCreateRequest(
                treeHandle.TreeId,
                path,
                desiredAccess,
                fileAttributes,
                shareAccess,
                createDisposition,
                createOptions);
            Smb2WriteRequest writeRequest = CreateRelatedWriteRequest(data, offset: 0);
            Smb2FlushRequest flushRequest = CreateRelatedFlushRequest();
            Smb2CloseRequest closeRequest = CreateRelatedCloseRequest();
            Smb2Header createHeader = session.CreateRequestHeader(Smb2Command.Create, treeHandle.TreeId, sessionId: session.SessionId!.Value);
            Smb2Header writeHeader = session.CreateRequestHeader(
                Smb2Command.Write,
                creditRequest: writeCredits,
                sessionId: session.SessionId!.Value,
                creditCharge: writeCreditCharge);
            writeHeader.Flags |= Smb2HeaderFlags.RelatedOperations;
            Smb2HeaderValidator.Validate(writeHeader);
            Smb2Header flushHeader = session.CreateRelatedRequestHeader(Smb2Command.Flush, sessionId: session.SessionId!.Value);
            Smb2Header closeHeader = session.CreateRelatedRequestHeader(Smb2Command.Close, sessionId: session.SessionId!.Value);
            Smb2CompoundPacket responsePacket = await _SendCompoundRequestAsync(
                new Smb2CompoundPacket(
                    new[]
                    {
                        new Smb2CompoundPacketEntry(createHeader, createRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(writeHeader, writeRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(flushHeader, flushRequest.ToByteArray()),
                        new Smb2CompoundPacketEntry(closeHeader, closeRequest.ToByteArray())
                    }),
                cancellationToken).ConfigureAwait(false);
            AssertCompoundResponseEntryCount(responsePacket, expectedCount: 4);

            Smb2CompoundPacketEntry createEntry = responsePacket.Entries[0];
            Smb2CompoundPacketEntry writeEntry = responsePacket.Entries[1];
            Smb2CompoundPacketEntry flushEntry = responsePacket.Entries[2];
            Smb2CompoundPacketEntry closeEntry = responsePacket.Entries[3];
            Smb2CreateResponse createResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(createEntry.Header.Status, _GetResponsePayloadBytes(createEntry), Smb2CreateResponse.ReadFrom);
            Smb2WriteResponse writeResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(writeEntry.Header.Status, _GetResponsePayloadBytes(writeEntry), Smb2WriteResponse.ReadFrom);
            Smb2FlushResponse flushResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(flushEntry.Header.Status, _GetResponsePayloadBytes(flushEntry), Smb2FlushResponse.ReadFrom);
            Smb2CloseResponse closeResponse = OpenCifsClientResponseDecoder.ReadSuccessResponseOrDefault(closeEntry.Header.Status, _GetResponsePayloadBytes(closeEntry), Smb2CloseResponse.ReadFrom);
            Exception? compoundFailure = null;
            OpenState? openState = null;
            uint writtenCount = 0;

            try
            {
                openState = session.ApplyCreateResult(treeHandle.TreeId, path, createEntry.Header.Status, createResponse);

                try
                {
                    writtenCount = session.ApplyWriteResult(openState.PersistentFileId, openState.VolatileFileId, writeEntry.Header.Status, writeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }

                try
                {
                    session.ApplyFlushResult(openState.PersistentFileId, openState.VolatileFileId, flushEntry.Header.Status, flushResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }
            catch (Exception exception)
            {
                compoundFailure ??= exception;
            }

            if (openState != null)
            {
                try
                {
                    session.ApplyCloseResult(openState.PersistentFileId, openState.VolatileFileId, closeEntry.Header.Status, closeResponse);
                }
                catch (Exception exception)
                {
                    compoundFailure ??= exception;
                }
            }

            if (compoundFailure != null)
            {
                throw compoundFailure;
            }

            return writtenCount;
        }

        private static void AssertCompoundResponseEntryCount(Smb2CompoundPacket responsePacket, int expectedCount)
        {
            if (responsePacket.Entries.Count != expectedCount)
            {
                throw new OpenCifsClientProtocolException(
                    "The managed direct-TCP client connection expected " +
                    expectedCount +
                    " SMB2 responses in the bounded compound-flow helper but received " +
                    responsePacket.Entries.Count +
                    '.');
            }
        }

        private static Smb2QueryInfoRequest CreateRelatedQueryInfoRequest(FileInformationClass informationClass, uint outputBufferLength)
        {
            Smb2QueryInfoRequest request = new Smb2QueryInfoRequest
            {
                InfoType = Smb2InfoType.File,
                FileInfoClass = informationClass,
                OutputBufferLength = outputBufferLength,
                AdditionalInformation = 0,
                Flags = 0,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId,
                InputBuffer = Array.Empty<byte>()
            };
            Smb2QueryInfoRequestValidator.Validate(request);
            return request;
        }

        private static Smb2ReadRequest CreateRelatedReadRequest(uint length, ulong offset, uint minimumCount)
        {
            Smb2ReadRequest request = new Smb2ReadRequest
            {
                Length = length,
                Offset = offset,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId,
                MinimumCount = minimumCount,
                Channel = 0,
                RemainingBytes = 0,
                ReadChannelInfo = Array.Empty<byte>()
            };
            Smb2ReadRequestValidator.Validate(request);
            return request;
        }

        private static Smb2WriteRequest CreateRelatedWriteRequest(byte[] data, ulong offset)
        {
            Smb2WriteRequest request = new Smb2WriteRequest
            {
                Offset = offset,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId,
                Flags = Smb2WriteFlags.None,
                Channel = 0,
                RemainingBytes = 0,
                WriteChannelInfo = Array.Empty<byte>(),
                DataBuffer = (byte[])data.Clone()
            };
            Smb2WriteRequestValidator.Validate(request);
            return request;
        }

        private static Smb2FlushRequest CreateRelatedFlushRequest()
        {
            Smb2FlushRequest request = new Smb2FlushRequest
            {
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId
            };
            Smb2FlushRequestValidator.Validate(request);
            return request;
        }

        private static Smb2CloseRequest CreateRelatedCloseRequest()
        {
            Smb2CloseRequest request = new Smb2CloseRequest
            {
                Flags = Smb2CloseFlags.None,
                PersistentFileId = RelatedCompoundFileId,
                VolatileFileId = RelatedCompoundFileId
            };
            Smb2CloseRequestValidator.Validate(request);
            return request;
        }

        private readonly Func<OpenCifsClientSession> _GetSession;
        private readonly Action<OpenCifsClientTreeHandle> _ValidateTreeHandle;
        private readonly Func<ushort, CancellationToken, Task> _EnsureCreditsAsync;
        private readonly Func<Smb2CompoundPacket, CancellationToken, Task<Smb2CompoundPacket>> _SendCompoundRequestAsync;
        private readonly Func<Smb2CompoundPacketEntry, byte[]> _GetResponsePayloadBytes;
    }
}
