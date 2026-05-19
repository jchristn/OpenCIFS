namespace OpenCIFS.Server
{
    using System;
    using System.Collections.Generic;
    using OpenCIFS.Protocol;
    using ProtocolFileAttributes = OpenCIFS.Protocol.FileAttributes;

    internal sealed class OpenCifsServerNamedPipeOperationService
    {
        private readonly IReadOnlyDictionary<string, OpenCifsServerNamedPipeEndpoint> _NamedPipeEndpoints;
        private readonly OpenCifsServerSharedState _SharedState;

        public OpenCifsServerNamedPipeOperationService(
            OpenCifsServerSharedState sharedState,
            IReadOnlyDictionary<string, OpenCifsServerNamedPipeEndpoint> namedPipeEndpoints)
        {
            _SharedState = sharedState ?? throw new ArgumentNullException(nameof(sharedState), "SharedState cannot be null.");
            _NamedPipeEndpoints = namedPipeEndpoints ?? throw new ArgumentNullException(nameof(namedPipeEndpoints), "NamedPipeEndpoints cannot be null.");
        }

        public OpenCifsServerOperationResult<Smb2CreateResponse> ExecuteCreate(OpenCifsServerNamedPipeCreateOperationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }

            if ((context.Request.CreateOptions & Smb2CreateOptions.DirectoryFile) != 0 ||
                context.Request.Name.Length == 0 ||
                context.Request.RequestedOplockLevel != Smb2OplockLevel.None ||
                context.CreateContexts.Count != 0)
            {
                return CreateCreateResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            if (context.Request.CreateDisposition != Smb2CreateDisposition.Open &&
                context.Request.CreateDisposition != Smb2CreateDisposition.OpenIf)
            {
                return CreateCreateResult(NtStatus.InvalidParameter, new Smb2CreateResponse());
            }

            string normalizedPipeName = context.Request.Name.Replace('/', '\\').Trim('\\');

            if (normalizedPipeName.Length == 0 ||
                normalizedPipeName.IndexOf('\\') >= 0 ||
                !_NamedPipeEndpoints.TryGetValue(normalizedPipeName, out OpenCifsServerNamedPipeEndpoint? endpoint) ||
                endpoint == null)
            {
                return CreateCreateResult(NtStatus.ObjectNameNotFound, new Smb2CreateResponse());
            }

            ulong fileId = _SharedState.AllocateFileId();
            OpenState openState = new OpenState();
            openState.Bind(fileId, fileId, normalizedPipeName);
            ServerOpenRecord openRecord = new ServerOpenRecord
            {
                OwnerHost = context.OwnerHost,
                SessionId = context.SessionRecord.State.SessionId,
                TreeId = context.TreeRecord.State.TreeId,
                ShareName = context.TreeRecord.ShareName,
                ShareRootPath = context.TreeRecord.ShareRootPath,
                DesiredAccess = context.Request.DesiredAccess,
                ShareAccess = context.Request.ShareAccess,
                CanRead = OpenCifsServerFilePolicy.CanRead(context.Request.DesiredAccess),
                CanWrite = OpenCifsServerFilePolicy.CanWrite(context.Request.DesiredAccess),
                CanReadData = OpenCifsServerFilePolicy.CanReadData(context.Request.DesiredAccess),
                CanWriteData = OpenCifsServerFilePolicy.CanWriteData(context.Request.DesiredAccess),
                CanDelete = OpenCifsServerFilePolicy.CanDelete(context.Request.DesiredAccess),
                IsDirectory = false,
                State = openState,
                IsNamedPipeEndpoint = true,
                NamedPipeEndpoint = endpoint,
                FullPath = normalizedPipeName
            };
            context.SessionRecord.Opens[fileId] = openRecord;

            ulong currentFileTime = unchecked((ulong)DateTimeOffset.UtcNow.UtcDateTime.ToFileTimeUtc());
            Smb2CreateResponse response = new Smb2CreateResponse
            {
                OplockLevel = Smb2OplockLevel.None,
                Flags = 0,
                CreateAction = Smb2CreateAction.Opened,
                CreationTime = currentFileTime,
                LastAccessTime = currentFileTime,
                LastWriteTime = currentFileTime,
                ChangeTime = currentFileTime,
                AllocationSize = 0,
                EndOfFile = 0,
                FileAttributes = ProtocolFileAttributes.Normal,
                PersistentFileId = fileId,
                VolatileFileId = fileId,
                CreateContexts = Array.Empty<byte>()
            };
            Smb2CreateResponseValidator.Validate(response);
            return CreateCreateResult(NtStatus.Success, response);
        }

        public OpenCifsServerOperationResult<Smb2IoctlResponse> ExecutePipeTransceiveIoctl(OpenCifsServerNamedPipeIoctlOperationContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException(nameof(context), "Context cannot be null.");
            }

            Smb2IoctlResponse defaultResponse = OpenCifsServerIoctlOperationService.CreateResponse(context.Request);

            if (context.OpenRecord == null ||
                !context.OpenRecord.IsNamedPipeEndpoint ||
                context.OpenRecord.NamedPipeEndpoint == null)
            {
                return CreateIoctlResult(NtStatus.NotSupported, defaultResponse);
            }

            OpenCifsServerNamedPipeRequestContext requestContext = new OpenCifsServerNamedPipeRequestContext(
                context.ServerName,
                context.SessionRecord.State.SessionId,
                context.TreeId,
                context.OpenRecord.State.Path,
                context.SessionRecord.UserName,
                context.SessionRecord.UserDomain,
                context.NegotiatedDialect,
                context.Request.InputBuffer,
                context.Request.MaxOutputResponse,
                context.AvailableShares);
            OpenCifsServerNamedPipeResponse endpointResponse = context.OpenRecord.NamedPipeEndpoint.Transceive(requestContext);
            byte[] outputBuffer = endpointResponse.OutputBuffer;

            if ((uint)outputBuffer.Length > context.Request.MaxOutputResponse)
            {
                return CreateIoctlResult(NtStatus.BufferOverflow, defaultResponse);
            }

            Smb2IoctlResponse response = OpenCifsServerIoctlOperationService.CreateResponse(
                context.Request.CtlCode,
                context.Request.PersistentFileId,
                context.Request.VolatileFileId,
                outputBuffer);
            return CreateIoctlResult(endpointResponse.Status, response);
        }

        private static OpenCifsServerOperationResult<Smb2CreateResponse> CreateCreateResult(NtStatus status, Smb2CreateResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2CreateResponse>
            {
                Status = status,
                Response = response
            };
        }

        private static OpenCifsServerOperationResult<Smb2IoctlResponse> CreateIoctlResult(NtStatus status, Smb2IoctlResponse response)
        {
            return new OpenCifsServerOperationResult<Smb2IoctlResponse>
            {
                Status = status,
                Response = response
            };
        }

    }
}
