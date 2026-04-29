namespace OpenCIFS.Security
{
    /// <summary>
    /// Holds computed NTLMv2 challenge responses and session-base key material.
    /// </summary>
    public sealed class NtlmV2ChallengeResponseSet
    {
        /// <summary>
        /// Initialize the NTLMv2 response set.
        /// </summary>
        /// <param name="responseKeyNt">NT response-key bytes.</param>
        /// <param name="responseKeyLm">LM response-key bytes.</param>
        /// <param name="ntChallengeResponse">Structured NT challenge response.</param>
        /// <param name="lmChallengeResponse">Serialized LM challenge response.</param>
        /// <param name="sessionBaseKey">Derived session-base key.</param>
        public NtlmV2ChallengeResponseSet(byte[] responseKeyNt, byte[] responseKeyLm, NtlmV2Response ntChallengeResponse, byte[] lmChallengeResponse, byte[] sessionBaseKey)
        {
            ResponseKeyNt = Validate(responseKeyNt, nameof(responseKeyNt));
            ResponseKeyLm = Validate(responseKeyLm, nameof(responseKeyLm));
            NtChallengeResponse = ntChallengeResponse ?? throw new ArgumentNullException(nameof(ntChallengeResponse), "NtChallengeResponse cannot be null.");
            LmChallengeResponse = Validate(lmChallengeResponse, nameof(lmChallengeResponse));
            SessionBaseKey = Validate(sessionBaseKey, nameof(sessionBaseKey));
        }

        /// <summary>
        /// NT response-key bytes.
        /// </summary>
        public byte[] ResponseKeyNt { get; }

        /// <summary>
        /// LM response-key bytes.
        /// </summary>
        public byte[] ResponseKeyLm { get; }

        /// <summary>
        /// Structured NT challenge response.
        /// </summary>
        public NtlmV2Response NtChallengeResponse { get; }

        /// <summary>
        /// Serialized LM challenge response bytes.
        /// </summary>
        public byte[] LmChallengeResponse { get; }

        /// <summary>
        /// Derived session-base key bytes.
        /// </summary>
        public byte[] SessionBaseKey { get; }

        private static byte[] Validate(byte[] value, string parameterName)
        {
            if (value == null)
            {
                throw new ArgumentNullException(parameterName, parameterName + " cannot be null.");
            }

            if (value.Length == 0)
            {
                throw new ArgumentOutOfRangeException(parameterName, parameterName + " must not be empty.");
            }

            return value;
        }
    }
}
