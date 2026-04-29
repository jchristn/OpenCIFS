namespace OpenCIFS.Client
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// High-level directory change-notify result entry.
    /// </summary>
    public sealed class OpenCifsClientChangeNotification
    {
        /// <summary>
        /// File action reported by the SMB2 CHANGE_NOTIFY response.
        /// </summary>
        public FileNotifyAction Action { get; set; }

        /// <summary>
        /// Relative path reported for the changed entry.
        /// </summary>
        public string FileName { get; set; } = string.Empty;
    }
}
