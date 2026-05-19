namespace OpenCIFS.Server
{
    internal sealed class PendingChangeNotifyDispatchTarget
    {
        public OpenCifsServerHost OwnerHost { get; set; } = null!;

        public PendingChangeNotifySubscription Subscription { get; set; } = null!;
    }
}
