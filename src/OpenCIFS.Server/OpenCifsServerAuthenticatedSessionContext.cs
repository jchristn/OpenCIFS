namespace OpenCIFS.Server
{
    /// <summary>
    /// Context passed to authenticated-session callbacks after credentials verify.
    /// </summary>
    public sealed class OpenCifsServerAuthenticatedSessionContext
    {
        /// <summary>
        /// Assigned session identifier.
        /// </summary>
        public ulong SessionId { get; set; }

        /// <summary>
        /// Authenticated user name.
        /// </summary>
        public string UserName { get; set; } = string.Empty;

        /// <summary>
        /// Authenticated user domain.
        /// </summary>
        public string UserDomain { get; set; } = string.Empty;

        /// <summary>
        /// Authentication flavor label.
        /// </summary>
        public string AuthenticationFlavor { get; set; } = string.Empty;
    }
}
