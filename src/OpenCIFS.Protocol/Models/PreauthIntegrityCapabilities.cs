namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB 3.1.1 preauthentication integrity capabilities context.
    /// </summary>
    public sealed class PreauthIntegrityCapabilities
    {
        /// <summary>
        /// Supported hash algorithms.
        /// </summary>
        public HashAlgorithmId[] HashAlgorithms
        {
            get
            {
                return _HashAlgorithms;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(HashAlgorithms), "HashAlgorithms cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(HashAlgorithms), "At least one hash algorithm is required.");
                }

                _HashAlgorithms = value;
            }
        }

        /// <summary>
        /// Negotiated salt bytes.
        /// </summary>
        public byte[] Salt
        {
            get
            {
                return _Salt;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Salt), "Salt cannot be null.");
                }

                _Salt = value;
            }
        }

        /// <summary>
        /// Serialize the context payload.
        /// </summary>
        /// <returns>Payload bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16((ushort)HashAlgorithms.Length);
            writer.WriteUInt16((ushort)Salt.Length);

            for (int index = 0; index < HashAlgorithms.Length; index++)
            {
                writer.WriteUInt16((ushort)HashAlgorithms[index]);
            }

            writer.WriteBytes(Salt);
            return writer.ToArray();
        }

        /// <summary>
        /// Parse the context payload from a binary buffer.
        /// </summary>
        /// <param name="buffer">Payload bytes.</param>
        /// <returns>Parsed context.</returns>
        public static PreauthIntegrityCapabilities ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort hashAlgorithmCount = reader.ReadUInt16();
            ushort saltLength = reader.ReadUInt16();

            if (hashAlgorithmCount == 0)
            {
                throw new ProtocolEncodingException("Preauthentication integrity capabilities require at least one hash algorithm.");
            }

            HashAlgorithmId[] algorithms = new HashAlgorithmId[hashAlgorithmCount];

            for (int index = 0; index < hashAlgorithmCount; index++)
            {
                algorithms[index] = (HashAlgorithmId)reader.ReadUInt16();
            }

            PreauthIntegrityCapabilities capabilities = new PreauthIntegrityCapabilities
            {
                HashAlgorithms = algorithms,
                Salt = reader.ReadBytes(saltLength)
            };

            return capabilities;
        }

        private HashAlgorithmId[] _HashAlgorithms = new HashAlgorithmId[] { HashAlgorithmId.Sha512 };
        private byte[] _Salt = Array.Empty<byte>();
    }
}

