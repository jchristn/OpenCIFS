namespace OpenCIFS.TestServer
{
    using System;
    using OpenCIFS.Protocol;
    using OpenCIFS.Server;

    internal sealed class TestServerState
    {
        public bool RunForever { get; set; } = true;

        public string ServerName { get; set; } = Environment.MachineName;

        public string BindAddress { get; set; } = "127.0.0.1";

        public int BindPort { get; set; } = 4450;

        public string ShareName { get; set; } = "public";

        public string UserName { get; set; } = "tester";

        public string UserDomain { get; set; } = string.Empty;

        public string Password { get; set; } = "Password123!";

        public SmbDialect MinimumDialect { get; set; } = SmbDialect.Smb2002;

        public SmbDialect MaximumDialect { get; set; } = SmbDialect.Smb311;

        public bool RequireSigning { get; set; } = true;

        public bool RequireEncryptionForSmb3 { get; set; } = true;

        public string RootPath { get; set; } = TestServerCommandProcessor.CreateTemporaryRootPath();

        public OpenCifsServerApplication? Application { get; set; }
    }
}
