namespace OpenCIFS.TestClient
{
    using OpenCIFS.Client;
    using OpenCIFS.Protocol;

    internal static class TestClientConnectionFactory
    {
        internal static OpenCifsClientCredential CreateCredential(string userName, string userDomain, string password)
        {
            return new OpenCifsClientCredential
            {
                UserName = userName,
                UserDomain = userDomain,
                Password = password
            };
        }

        internal static OpenCifsClientBuilder CreateClientBuilder(
            string serverName,
            int serverPort,
            SmbDialect minimumDialect,
            SmbDialect maximumDialect,
            bool requireSigning,
            bool preferEncryption,
            int connectTimeoutMs)
        {
            return new OpenCifsClientBuilder()
                .WithServer(serverName, serverPort)
                .WithDialectRange(minimumDialect, maximumDialect)
                .WithSigningRequired(requireSigning)
                .WithPreferredEncryption(preferEncryption)
                .WithConnectTimeoutMs(connectTimeoutMs);
        }
    }
}
