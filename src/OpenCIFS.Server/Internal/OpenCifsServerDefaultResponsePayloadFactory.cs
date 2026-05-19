namespace OpenCIFS.Server
{
    using System;
    using OpenCIFS.Protocol;

    internal static class OpenCifsServerDefaultResponsePayloadFactory
    {
        public static byte[] CreateDefaultResponsePayload(Smb2Command command)
        {
            if (!TryCreateDefaultResponsePayload(command, out byte[]? payload) || payload == null)
            {
                throw new ProtocolValidationException("No default error payload is available for the specified SMB2 command.", nameof(command));
            }

            return payload;
        }

        public static bool TryCreateDefaultResponsePayload(Smb2Command command, out byte[]? payload)
        {
            switch (command)
            {
                case Smb2Command.SessionSetup:
                    payload = new Smb2SessionSetupResponse().ToByteArray();
                    return true;
                case Smb2Command.Logoff:
                    payload = new Smb2LogoffResponse().ToByteArray();
                    return true;
                case Smb2Command.Echo:
                    payload = new Smb2EchoResponse().ToByteArray();
                    return true;
                case Smb2Command.TreeConnect:
                    payload = new Smb2TreeConnectResponse().ToByteArray();
                    return true;
                case Smb2Command.TreeDisconnect:
                    payload = new Smb2TreeDisconnectResponse().ToByteArray();
                    return true;
                case Smb2Command.Create:
                    payload = new Smb2CreateResponse().ToByteArray();
                    return true;
                case Smb2Command.Read:
                    payload = new Smb2ReadResponse().ToByteArray();
                    return true;
                case Smb2Command.Write:
                    payload = new Smb2WriteResponse().ToByteArray();
                    return true;
                case Smb2Command.Flush:
                    payload = new Smb2FlushResponse().ToByteArray();
                    return true;
                case Smb2Command.Close:
                    payload = new Smb2CloseResponse().ToByteArray();
                    return true;
                case Smb2Command.Lock:
                    payload = new Smb2LockResponse().ToByteArray();
                    return true;
                case Smb2Command.Ioctl:
                    payload = new Smb2IoctlResponse().ToByteArray();
                    return true;
                case Smb2Command.QueryInfo:
                    payload = new Smb2QueryInfoResponse().ToByteArray();
                    return true;
                case Smb2Command.SetInfo:
                    payload = new Smb2SetInfoResponse().ToByteArray();
                    return true;
                case Smb2Command.QueryDirectory:
                    payload = new Smb2QueryDirectoryResponse().ToByteArray();
                    return true;
                default:
                    payload = null;
                    return false;
            }
        }
    }
}
