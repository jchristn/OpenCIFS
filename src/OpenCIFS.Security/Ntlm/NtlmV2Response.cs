namespace OpenCIFS.Security
{
    using OpenCIFS.Protocol;

    /// <summary>
    /// Represents an NTLMv2 NT challenge-response value.
    /// </summary>
    public sealed class NtlmV2Response
    {
        /// <summary>
        /// Sixteen-byte NT proof string.
        /// </summary>
        public byte[] Proof
        {
            get
            {
                return _Proof;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Proof), "Proof cannot be null.");
                }

                if (value.Length != 16)
                {
                    throw new ArgumentOutOfRangeException(nameof(Proof), "Proof must be exactly 16 bytes.");
                }

                _Proof = value;
            }
        }

        /// <summary>
        /// Embedded client-challenge structure.
        /// </summary>
        public NtlmV2ClientChallenge ClientChallenge
        {
            get
            {
                return _ClientChallenge;
            }
            set
            {
                _ClientChallenge = value ?? throw new ArgumentNullException(nameof(ClientChallenge), "ClientChallenge cannot be null.");
            }
        }

        /// <summary>
        /// Serialize the NTLMv2 response to its wire format.
        /// </summary>
        /// <returns>Serialized NTLMv2 response bytes.</returns>
        public byte[] ToByteArray()
        {
            byte[] clientChallengeBytes = ClientChallenge.ToByteArray();
            byte[] buffer = new byte[Proof.Length + clientChallengeBytes.Length];
            Buffer.BlockCopy(Proof, 0, buffer, 0, Proof.Length);
            Buffer.BlockCopy(clientChallengeBytes, 0, buffer, Proof.Length, clientChallengeBytes.Length);
            return buffer;
        }

        /// <summary>
        /// Parse an NTLMv2 response from a binary buffer.
        /// </summary>
        /// <param name="buffer">Serialized NTLMv2 response bytes.</param>
        /// <returns>Parsed NTLMv2 response.</returns>
        public static NtlmV2Response ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 48)
            {
                throw new ProtocolEncodingException("The buffer does not contain a complete NTLMv2 response.");
            }

            NtlmV2Response response = new NtlmV2Response
            {
                Proof = buffer.Slice(0, 16).ToArray(),
                ClientChallenge = NtlmV2ClientChallenge.ReadFrom(buffer.Slice(16))
            };

            return response;
        }

        private byte[] _Proof = new byte[16];
        private NtlmV2ClientChallenge _ClientChallenge = new NtlmV2ClientChallenge();
    }
}
