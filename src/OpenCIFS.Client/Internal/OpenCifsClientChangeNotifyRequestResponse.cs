namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientChangeNotifyRequestResponse
    {
        public OpenCifsClientChangeNotifyRequestResponse(Smb2Header responseHeader, byte[] responsePayload, bool cancelledByClient)
        {
            ResponseHeader = responseHeader ?? throw new ArgumentNullException(nameof(responseHeader));
            ResponsePayload = responsePayload ?? throw new ArgumentNullException(nameof(responsePayload));
            CancelledByClient = cancelledByClient;
        }

        public Smb2Header ResponseHeader { get; }

        public byte[] ResponsePayload { get; }

        public bool CancelledByClient { get; }
    }
}
