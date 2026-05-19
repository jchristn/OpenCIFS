namespace OpenCIFS.Server
{
    using OpenCIFS.Protocol;

    internal struct ChangeNotifyEvent
    {
        public string FullPath;

        public FileNotifyAction Action;

        public FileNotifyChangeFilter Filter;
    }
}
