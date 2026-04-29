namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB signing capabilities context.
    /// </summary>
    public sealed class SigningCapabilities
    {
        /// <summary>
        /// Supported signing algorithms.
        /// </summary>
        public SigningAlgorithmId[] SigningAlgorithms
        {
            get
            {
                return _SigningAlgorithms;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(SigningAlgorithms), "SigningAlgorithms cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(SigningAlgorithms), "At least one signing algorithm is required.");
                }

                _SigningAlgorithms = value;
            }
        }

        /// <summary>
        /// Serialize the context payload.
        /// </summary>
        /// <returns>Payload bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16((ushort)SigningAlgorithms.Length);
            writer.WriteUInt16(0);

            for (int index = 0; index < SigningAlgorithms.Length; index++)
            {
                writer.WriteUInt16((ushort)SigningAlgorithms[index]);
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse the context payload from a binary buffer.
        /// </summary>
        /// <param name="buffer">Payload bytes.</param>
        /// <returns>Parsed context.</returns>
        public static SigningCapabilities ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort signingAlgorithmCount = reader.ReadUInt16();
            reader.Skip(2);

            if (signingAlgorithmCount == 0)
            {
                throw new ProtocolEncodingException("Signing capabilities require at least one signing algorithm.");
            }

            SigningAlgorithmId[] algorithms = new SigningAlgorithmId[signingAlgorithmCount];

            for (int index = 0; index < signingAlgorithmCount; index++)
            {
                algorithms[index] = (SigningAlgorithmId)reader.ReadUInt16();
            }

            SigningCapabilities capabilities = new SigningCapabilities
            {
                SigningAlgorithms = algorithms
            };

            return capabilities;
        }

        private SigningAlgorithmId[] _SigningAlgorithms = new SigningAlgorithmId[] { SigningAlgorithmId.HmacSha256 };
    }
}
