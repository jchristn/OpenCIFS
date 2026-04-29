namespace OpenCIFS.Security
{
    using System.Security.Cryptography;
    using System.Text;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Creates and verifies NTLMv2 challenge-response values.
    /// </summary>
    public static class NtlmV2Authentication
    {
        /// <summary>
        /// Compute the NT password hash used by NTLM and NTLMv2.
        /// </summary>
        /// <param name="password">User password.</param>
        /// <returns>Sixteen-byte NT password hash.</returns>
        public static byte[] ComputeNtHash(string password)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password), "Password cannot be null.");
            }

            return Md4.HashData(Encoding.Unicode.GetBytes(password));
        }

        /// <summary>
        /// Compute the NTLMv2 response key for the supplied credentials.
        /// </summary>
        /// <param name="password">User password.</param>
        /// <param name="userName">Account name.</param>
        /// <param name="userDomain">Account domain.</param>
        /// <returns>Sixteen-byte NTLMv2 response key.</returns>
        public static byte[] ComputeResponseKey(string password, string userName, string userDomain)
        {
            if (password == null)
            {
                throw new ArgumentNullException(nameof(password), "Password cannot be null.");
            }

            if (userName == null)
            {
                throw new ArgumentNullException(nameof(userName), "UserName cannot be null.");
            }

            if (userDomain == null)
            {
                throw new ArgumentNullException(nameof(userDomain), "UserDomain cannot be null.");
            }

            byte[] ntHash = ComputeNtHash(password);
            string normalizedIdentity = userName.ToUpperInvariant() + userDomain;
            byte[] identityBytes = Encoding.Unicode.GetBytes(normalizedIdentity);
            return HmacMd5.HashData(ntHash, identityBytes);
        }

        /// <summary>
        /// Compute NTLMv2 NT and LM challenge responses for a server challenge.
        /// </summary>
        /// <param name="password">User password.</param>
        /// <param name="userName">Account name.</param>
        /// <param name="userDomain">Account domain.</param>
        /// <param name="serverChallenge">Eight-byte server challenge.</param>
        /// <param name="clientChallenge">Client-challenge structure.</param>
        /// <returns>Computed response set.</returns>
        public static NtlmV2ChallengeResponseSet CreateChallengeResponseSet(string password, string userName, string userDomain, ReadOnlySpan<byte> serverChallenge, NtlmV2ClientChallenge clientChallenge)
        {
            if (clientChallenge == null)
            {
                throw new ArgumentNullException(nameof(clientChallenge), "ClientChallenge cannot be null.");
            }

            ValidateServerChallenge(serverChallenge);
            byte[] responseKeyNt = ComputeResponseKey(password, userName, userDomain);
            byte[] responseKeyLm = new byte[responseKeyNt.Length];
            Buffer.BlockCopy(responseKeyNt, 0, responseKeyLm, 0, responseKeyNt.Length);
            byte[] clientChallengeBytes = clientChallenge.ToByteArray();
            byte[] ntProofInput = Combine(serverChallenge, clientChallengeBytes);
            byte[] ntProof = HmacMd5.HashData(responseKeyNt, ntProofInput);
            NtlmV2Response ntResponse = new NtlmV2Response
            {
                Proof = ntProof,
                ClientChallenge = clientChallenge
            };

            byte[] lmProofInput = Combine(serverChallenge, clientChallenge.ClientChallenge);
            byte[] lmProof = HmacMd5.HashData(responseKeyLm, lmProofInput);
            byte[] lmChallengeResponse = Combine(lmProof, clientChallenge.ClientChallenge);
            byte[] sessionBaseKey = HmacMd5.HashData(responseKeyNt, ntProof);
            return new NtlmV2ChallengeResponseSet(responseKeyNt, responseKeyLm, ntResponse, lmChallengeResponse, sessionBaseKey);
        }

        /// <summary>
        /// Verify serialized NTLMv2 responses for a server challenge.
        /// </summary>
        /// <param name="password">User password.</param>
        /// <param name="userName">Account name.</param>
        /// <param name="userDomain">Account domain.</param>
        /// <param name="serverChallenge">Eight-byte server challenge.</param>
        /// <param name="ntChallengeResponse">Serialized NT challenge response.</param>
        /// <param name="lmChallengeResponse">Serialized LM challenge response.</param>
        /// <param name="verifiedResponseSet">Computed response set when verification succeeds.</param>
        /// <returns><c>true</c> if the responses are valid.</returns>
        public static bool TryVerifyChallengeResponseSet(string password, string userName, string userDomain, ReadOnlySpan<byte> serverChallenge, ReadOnlySpan<byte> ntChallengeResponse, ReadOnlySpan<byte> lmChallengeResponse, out NtlmV2ChallengeResponseSet? verifiedResponseSet)
        {
            verifiedResponseSet = null;

            bool lmChallengeResponseOmitted = lmChallengeResponse.Length == 0 ||
                (lmChallengeResponse.Length == 24 && IsAllZero(lmChallengeResponse));

            if (!lmChallengeResponseOmitted && lmChallengeResponse.Length != 24)
            {
                return false;
            }

            NtlmV2Response parsedNtResponse;

            try
            {
                parsedNtResponse = NtlmV2Response.ReadFrom(ntChallengeResponse.ToArray());
            }
            catch (ProtocolEncodingException)
            {
                return false;
            }

            NtlmV2ChallengeResponseSet expected = CreateChallengeResponseSet(password, userName, userDomain, serverChallenge, parsedNtResponse.ClientChallenge);
            byte[] expectedNtResponse = expected.NtChallengeResponse.ToByteArray();

            if (!CryptographicOperations.FixedTimeEquals(expectedNtResponse, ntChallengeResponse))
            {
                return false;
            }

            if (!lmChallengeResponseOmitted &&
                !CryptographicOperations.FixedTimeEquals(expected.LmChallengeResponse, lmChallengeResponse))
            {
                return false;
            }

            verifiedResponseSet = expected;
            return true;
        }

        private static void ValidateServerChallenge(ReadOnlySpan<byte> serverChallenge)
        {
            if (serverChallenge.Length != 8)
            {
                throw new ArgumentOutOfRangeException(nameof(serverChallenge), "ServerChallenge must be exactly 8 bytes.");
            }
        }

        private static byte[] Combine(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
        {
            byte[] buffer = new byte[first.Length + second.Length];
            first.CopyTo(buffer.AsSpan(0, first.Length));
            second.CopyTo(buffer.AsSpan(first.Length, second.Length));
            return buffer;
        }

        private static bool IsAllZero(ReadOnlySpan<byte> value)
        {
            for (int index = 0; index < value.Length; index++)
            {
                if (value[index] != 0)
                {
                    return false;
                }
            }

            return true;
        }
    }
}
