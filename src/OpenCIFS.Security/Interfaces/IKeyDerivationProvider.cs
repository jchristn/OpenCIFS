namespace OpenCIFS.Security
{
    /// <summary>
    /// Derives SMB session keys for signing and encryption.
    /// </summary>
    public interface IKeyDerivationProvider
    {
        /// <summary>
        /// Derive a session subkey from a session secret, label, and context.
        /// </summary>
        /// <param name="sessionSecret">Session secret bytes.</param>
        /// <param name="label">Key label bytes.</param>
        /// <param name="context">Key derivation context bytes.</param>
        /// <param name="outputLength">Desired derived key length in bytes.</param>
        /// <returns>Derived key bytes.</returns>
        byte[] DeriveKey(ReadOnlySpan<byte> sessionSecret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int outputLength);
    }
}

