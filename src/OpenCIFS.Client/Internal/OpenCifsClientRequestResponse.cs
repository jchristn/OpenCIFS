namespace OpenCIFS.Client
{
    using System;
    using OpenCIFS.Protocol;

    internal sealed class OpenCifsClientRequestResponse
    {
        public OpenCifsClientRequestResponse(Smb2Header responseHeader, byte[] responsePayload)
        {
            ResponseHeader = responseHeader ?? throw new ArgumentNullException(nameof(responseHeader));
            ResponsePayload = responsePayload ?? throw new ArgumentNullException(nameof(responsePayload));
        }

        public Smb2Header ResponseHeader { get; }

        public byte[] ResponsePayload { get; }
    }
}
