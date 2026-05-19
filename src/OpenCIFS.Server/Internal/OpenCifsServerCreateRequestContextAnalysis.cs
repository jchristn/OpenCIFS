namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsServerCreateRequestContextAnalysis
    {
        public Smb2CreateContext[] CreateContexts { get; set; } = Array.Empty<Smb2CreateContext>();

        public bool DurableHandleRequested { get; set; }

        public Smb2DurableHandleRequestV2Context? DurableHandleRequestV2Context { get; set; }

        public Smb2DurableHandleReconnectContext? DurableHandleReconnectContext { get; set; }

        public Smb2DurableHandleReconnectV2Context? DurableHandleReconnectV2Context { get; set; }

        public Smb2CreateRequestLeaseContext? LeaseRequestContext { get; set; }
    }
}
