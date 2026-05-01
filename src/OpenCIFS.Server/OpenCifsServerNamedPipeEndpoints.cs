namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Built-in named-pipe endpoint helpers for bounded OpenCIFS server scenarios.
    /// </summary>
    public static class OpenCifsServerNamedPipeEndpoints
    {
        /// <summary>
        /// Default pipe name for the bounded UTF-8 echo endpoint.
        /// </summary>
        public const string DefaultUtf8EchoPipeName = "opencifs.echo";

        /// <summary>
        /// Create a bounded SRVSVC share-enumeration endpoint backed by the server's current share snapshots.
        /// </summary>
        /// <returns>Named-pipe endpoint registration.</returns>
        public static OpenCifsServerNamedPipeEndpoint CreateSrvsvcShareEnumerationEndpoint()
        {
            return new OpenCifsServerNamedPipeEndpoint("srvsvc", HandleSrvsvcShareEnumerationTransceive);
        }

        /// <summary>
        /// Create a bounded UTF-8 echo endpoint for manual testing and generic pipe-transceive coverage.
        /// </summary>
        /// <param name="pipeName">Named-pipe endpoint name.</param>
        /// <returns>Named-pipe endpoint registration.</returns>
        public static OpenCifsServerNamedPipeEndpoint CreateUtf8EchoEndpoint(string pipeName = DefaultUtf8EchoPipeName)
        {
            return new OpenCifsServerNamedPipeEndpoint(pipeName, HandleUtf8EchoTransceive);
        }

        private static OpenCifsServerNamedPipeResponse HandleSrvsvcShareEnumerationTransceive(OpenCifsServerNamedPipeRequestContext context)
        {
            ReadOnlyMemory<byte> inputBuffer = context.InputBuffer;

            if (inputBuffer.Length == 0)
            {
                return new OpenCifsServerNamedPipeResponse(NtStatus.InvalidParameter);
            }

            DceRpcPacketType packetType = (DceRpcPacketType)inputBuffer.Span[2];

            if (packetType == DceRpcPacketType.Bind)
            {
                DceRpcBindRequest bindRequest = DceRpcBindRequest.ReadFrom(inputBuffer);

                if (bindRequest.InterfaceId != DceRpcConstants.SrvsvcInterface ||
                    bindRequest.TransferSyntaxId != DceRpcConstants.NdrTransferSyntax)
                {
                    return new OpenCifsServerNamedPipeResponse(NtStatus.NotSupported);
                }

                DceRpcBindAck bindAck = new DceRpcBindAck
                {
                    CallId = bindRequest.CallId,
                    MaximumTransmitFragment = bindRequest.MaximumTransmitFragment,
                    MaximumReceiveFragment = bindRequest.MaximumReceiveFragment,
                    ResultCode = 0,
                    ReasonCode = 0
                };
                return OpenCifsServerNamedPipeResponse.Success(bindAck.ToByteArray());
            }

            if (packetType != DceRpcPacketType.Request)
            {
                return new OpenCifsServerNamedPipeResponse(NtStatus.NotSupported);
            }

            DceRpcRequestPdu requestPdu = DceRpcRequestPdu.ReadFrom(inputBuffer);

            if (requestPdu.OperationNumber == SrvsvcNetrShareEnumRequest.OperationNumber)
            {
                _ = SrvsvcNetrShareEnumRequest.ReadFrom(requestPdu.StubData);
                List<SrvsvcShareInfo1> shares = new List<SrvsvcShareInfo1>(context.AvailableShares.Count);

                for (int index = 0; index < context.AvailableShares.Count; index++)
                {
                    OpenCifsServerShareInfo share = context.AvailableShares[index];
                    shares.Add(new SrvsvcShareInfo1
                    {
                        Name = share.ShareName,
                        Type = DetermineSrvsvcShareType(share),
                        Remark = string.Empty
                    });
                }

                SrvsvcNetrShareEnumResponse shareResponse = SrvsvcNetrShareEnumResponse.Create(
                    shares,
                    totalEntries: (uint)shares.Count,
                    resumeHandle: null,
                    returnCode: 0);
                DceRpcResponsePdu responsePdu = new DceRpcResponsePdu
                {
                    CallId = requestPdu.CallId,
                    ContextId = requestPdu.ContextId,
                    StubData = shareResponse.ToByteArray()
                };
                return OpenCifsServerNamedPipeResponse.Success(responsePdu.ToByteArray());
            }

            if (requestPdu.OperationNumber == SrvsvcNetrShareGetInfoRequest.OperationNumber)
            {
                SrvsvcNetrShareGetInfoRequest request = SrvsvcNetrShareGetInfoRequest.ReadFrom(requestPdu.StubData);
                OpenCifsServerShareInfo? share = null;

                for (int index = 0; index < context.AvailableShares.Count; index++)
                {
                    if (string.Equals(context.AvailableShares[index].ShareName, request.ShareName, StringComparison.OrdinalIgnoreCase))
                    {
                        share = context.AvailableShares[index];
                        break;
                    }
                }

                SrvsvcNetrShareGetInfoResponse shareResponse = share == null
                    ? SrvsvcNetrShareGetInfoResponse.Create(null, SrvsvcNetrShareGetInfoResponse.NerrNetNameNotFound)
                    : SrvsvcNetrShareGetInfoResponse.Create(
                        new SrvsvcShareInfo2
                        {
                            Name = share.ShareName,
                            Type = DetermineSrvsvcShareType(share),
                            Remark = string.Empty,
                            Permissions = 0,
                            MaximumUses = UInt32.MaxValue,
                            CurrentUses = 0,
                            Path = share.RootPath,
                            Password = string.Empty
                        },
                        SrvsvcNetrShareGetInfoResponse.ErrorSuccess);
                DceRpcResponsePdu responsePdu = new DceRpcResponsePdu
                {
                    CallId = requestPdu.CallId,
                    ContextId = requestPdu.ContextId,
                    StubData = shareResponse.ToByteArray()
                };
                return OpenCifsServerNamedPipeResponse.Success(responsePdu.ToByteArray());
            }

            return new OpenCifsServerNamedPipeResponse(NtStatus.NotSupported);
        }

        private static uint DetermineSrvsvcShareType(OpenCifsServerShareInfo share)
        {
            if (share == null)
            {
                throw new ArgumentNullException(nameof(share), "Share cannot be null.");
            }

            if (string.Equals(share.ShareName, "IPC$", StringComparison.OrdinalIgnoreCase))
            {
                return 0x80000003U;
            }

            return 0x00000000U;
        }

        private static OpenCifsServerNamedPipeResponse HandleUtf8EchoTransceive(OpenCifsServerNamedPipeRequestContext context)
        {
            return OpenCifsServerNamedPipeResponse.Success(context.InputBuffer.ToArray());
        }
    }
}
