namespace OpenCIFS.Protocol
{
    using System;

    /// <summary>
    /// SMB 3.1.1 encryption capabilities context.
    /// </summary>
    public sealed class EncryptionCapabilities
    {
        /// <summary>
        /// Supported cipher algorithms.
        /// </summary>
        public SmbCipherAlgorithmId[] Ciphers
        {
            get
            {
                return _Ciphers;
            }
            set
            {
                if (value == null)
                {
                    throw new ArgumentNullException(nameof(Ciphers), "Ciphers cannot be null.");
                }

                if (value.Length == 0)
                {
                    throw new ArgumentOutOfRangeException(nameof(Ciphers), "At least one cipher is required.");
                }

                _Ciphers = value;
            }
        }

        /// <summary>
        /// Serialize the context payload.
        /// </summary>
        /// <returns>Payload bytes.</returns>
        public byte[] ToByteArray()
        {
            LittleEndianWriter writer = new LittleEndianWriter();
            writer.WriteUInt16((ushort)Ciphers.Length);

            for (int index = 0; index < Ciphers.Length; index++)
            {
                writer.WriteUInt16((ushort)Ciphers[index]);
            }

            return writer.ToArray();
        }

        /// <summary>
        /// Parse the context payload from a binary buffer.
        /// </summary>
        /// <param name="buffer">Payload bytes.</param>
        /// <returns>Parsed context.</returns>
        public static EncryptionCapabilities ReadFrom(ReadOnlyMemory<byte> buffer)
        {
            if (buffer.Length < 2)
            {
                throw new ProtocolEncodingException("The encryption capabilities payload is truncated.");
            }

            LittleEndianReader reader = new LittleEndianReader(buffer);
            ushort cipherCount = reader.ReadUInt16();

            if (cipherCount == 0)
            {
                throw new ProtocolEncodingException("Encryption capabilities require at least one cipher algorithm.");
            }

            if (buffer.Length < 2 + cipherCount * 2)
            {
                throw new ProtocolEncodingException("The encryption capabilities payload is truncated for the declared cipher count.");
            }

            SmbCipherAlgorithmId[] ciphers = new SmbCipherAlgorithmId[cipherCount];

            for (int index = 0; index < cipherCount; index++)
            {
                ciphers[index] = (SmbCipherAlgorithmId)reader.ReadUInt16();
            }

            return new EncryptionCapabilities
            {
                Ciphers = ciphers
            };
        }

        private SmbCipherAlgorithmId[] _Ciphers = new SmbCipherAlgorithmId[] { SmbCipherAlgorithmId.Aes128Ccm };
    }
}
