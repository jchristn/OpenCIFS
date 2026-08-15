namespace OpenCIFS.Core.Tests.Shared
{
    /// <summary>
    /// Stable shared defaults for OpenCIFS test credentials, shares, and server identity.
    /// </summary>
    public static class TestEnvironmentDefaults
    {
        /// <summary>
        /// Default server name for managed loopback and direct-TCP suites.
        /// </summary>
        public const string DefaultServerName = "LAB-SERVER";

        /// <summary>
        /// Default share name for managed loopback and direct-TCP suites.
        /// </summary>
        public const string DefaultShareName = "public";

        /// <summary>
        /// Default test user name.
        /// </summary>
        public const string DefaultUserName = "alice";

        /// <summary>
        /// Default test user domain.
        /// </summary>
        public const string DefaultUserDomain = "WORKGROUP";

        /// <summary>
        /// Default test password.
        /// </summary>
        public const string DefaultPassword = "Password123!";

        /// <summary>
        /// Deterministically invalid alternate password for negative-path tests.
        /// </summary>
        public const string InvalidPassword = "WrongPassword123!";
    }
}
