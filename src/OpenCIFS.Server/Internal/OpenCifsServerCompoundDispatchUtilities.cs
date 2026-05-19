namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    internal static class OpenCifsServerCompoundDispatchUtilities
    {
        internal static bool CommandRequiresSessionId(Smb2Command command)
        {
            switch (command)
            {
                case Smb2Command.TreeConnect:
                case Smb2Command.TreeDisconnect:
                case Smb2Command.Create:
                case Smb2Command.Read:
                case Smb2Command.Write:
                case Smb2Command.Flush:
                case Smb2Command.Close:
                case Smb2Command.Lock:
                case Smb2Command.QueryInfo:
                case Smb2Command.SetInfo:
                case Smb2Command.QueryDirectory:
                case Smb2Command.Echo:
                case Smb2Command.Logoff:
                    return true;
                default:
                    return false;
            }
        }

        internal static bool CommandRequiresTreeId(Smb2Command command)
        {
            switch (command)
            {
                case Smb2Command.TreeDisconnect:
                case Smb2Command.Create:
                case Smb2Command.Read:
                case Smb2Command.Write:
                case Smb2Command.Flush:
                case Smb2Command.Close:
                case Smb2Command.Lock:
                case Smb2Command.Ioctl:
                case Smb2Command.QueryInfo:
                case Smb2Command.SetInfo:
                case Smb2Command.QueryDirectory:
                    return true;
                default:
                    return false;
            }
        }

        internal static bool CommandRequiresFileId(Smb2Command command)
        {
            switch (command)
            {
                case Smb2Command.Read:
                case Smb2Command.Write:
                case Smb2Command.Flush:
                case Smb2Command.Close:
                case Smb2Command.Lock:
                case Smb2Command.Ioctl:
                case Smb2Command.QueryInfo:
                case Smb2Command.SetInfo:
                case Smb2Command.QueryDirectory:
                    return true;
                default:
                    return false;
            }
        }

        internal static Smb2Header CloneHeader(Smb2Header header)
        {
            return new Smb2Header
            {
                CreditCharge = header.CreditCharge,
                Status = header.Status,
                Command = header.Command,
                CreditRequest = header.CreditRequest,
                Flags = header.Flags,
                NextCommand = header.NextCommand,
                MessageId = header.MessageId,
                ProcessId = header.ProcessId,
                TreeId = header.TreeId,
                SessionId = header.SessionId,
                Signature = (byte[])header.Signature.Clone()
            };
        }
    }
}
