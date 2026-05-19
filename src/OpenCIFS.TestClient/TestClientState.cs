namespace OpenCIFS.TestClient
{
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;

    internal sealed class TestClientState
    {
        public bool RunForever { get; set; } = true;

        public string ServerName { get; set; } = "127.0.0.1";

        public int ServerPort { get; set; } = 4450;

        public string UserName { get; set; } = "tester";

        public string UserDomain { get; set; } = string.Empty;

        public string Password { get; set; } = "Password123!";

        public SmbDialect MinimumDialect { get; set; } = SmbDialect.Smb2002;

        public SmbDialect MaximumDialect { get; set; } = SmbDialect.Smb311;

        public bool RequireSigning { get; set; } = true;

        public bool PreferEncryption { get; set; } = true;

        public int ConnectTimeoutMs { get; set; } = 30000;

        public string CurrentRemotePath { get; set; } = "/";

        public OpenCifsClient? Client { get; set; }

        public OpenCifsShareSession? ShareSession { get; set; }
    }
}
