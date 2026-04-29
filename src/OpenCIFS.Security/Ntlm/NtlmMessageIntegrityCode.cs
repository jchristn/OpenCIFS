namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Computes and verifies NTLM message-integrity codes.
    /// </summary>
    public static class NtlmMessageIntegrityCode
    {
        /// <summary>
        /// Compute an NTLM MIC over the negotiate, challenge, and authenticate messages.
        /// </summary>
        /// <param name="exportedSessionKey">Exported session key bytes.</param>
        /// <param name="negotiateMessage">Serialized NTLM negotiate message.</param>
        /// <param name="challengeMessage">Serialized NTLM challenge message.</param>
        /// <param name="authenticateMessageWithZeroMic">Serialized authenticate message with the MIC field zeroed.</param>
        /// <returns>Sixteen-byte MIC value.</returns>
        public static byte[] Compute(ReadOnlySpan<byte> exportedSessionKey, ReadOnlySpan<byte> negotiateMessage, ReadOnlySpan<byte> challengeMessage, ReadOnlySpan<byte> authenticateMessageWithZeroMic)
        {
            byte[] payload = new byte[negotiateMessage.Length + challengeMessage.Length + authenticateMessageWithZeroMic.Length];
            negotiateMessage.CopyTo(payload.AsSpan(0, negotiateMessage.Length));
            challengeMessage.CopyTo(payload.AsSpan(negotiateMessage.Length, challengeMessage.Length));
            authenticateMessageWithZeroMic.CopyTo(payload.AsSpan(negotiateMessage.Length + challengeMessage.Length, authenticateMessageWithZeroMic.Length));
            return HmacMd5.HashData(exportedSessionKey, payload);
        }

        /// <summary>
        /// Verify an NTLM MIC over the negotiate, challenge, and authenticate messages.
        /// </summary>
        /// <param name="exportedSessionKey">Exported session key bytes.</param>
        /// <param name="negotiateMessage">Serialized NTLM negotiate message.</param>
        /// <param name="challengeMessage">Serialized NTLM challenge message.</param>
        /// <param name="authenticateMessageWithZeroMic">Serialized authenticate message with the MIC field zeroed.</param>
        /// <param name="messageIntegrityCode">Expected MIC value.</param>
        /// <returns><c>true</c> if the MIC is valid.</returns>
        public static bool Verify(ReadOnlySpan<byte> exportedSessionKey, ReadOnlySpan<byte> negotiateMessage, ReadOnlySpan<byte> challengeMessage, ReadOnlySpan<byte> authenticateMessageWithZeroMic, ReadOnlySpan<byte> messageIntegrityCode)
        {
            if (messageIntegrityCode.Length != 16)
            {
                return false;
            }

            byte[] expected = Compute(exportedSessionKey, negotiateMessage, challengeMessage, authenticateMessageWithZeroMic);
            return CryptographicOperations.FixedTimeEquals(expected, messageIntegrityCode);
        }
    }
}
