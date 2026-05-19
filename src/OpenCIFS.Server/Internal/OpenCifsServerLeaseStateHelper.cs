namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    internal static class OpenCifsServerLeaseStateHelper
    {
        public static Smb2LeaseState Normalize(Smb2LeaseState leaseState)
        {
            return leaseState & (Smb2LeaseState.ReadCaching | Smb2LeaseState.HandleCaching | Smb2LeaseState.WriteCaching);
        }

        public static bool SupportsDurableReconnect(Smb2LeaseState leaseState)
        {
            return (Normalize(leaseState) & Smb2LeaseState.HandleCaching) != 0;
        }
    }
}
