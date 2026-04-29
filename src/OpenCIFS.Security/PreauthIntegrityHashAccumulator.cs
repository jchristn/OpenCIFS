namespace OpenCIFS.Security
{
    using System;
    using System.Security.Cryptography;
    using OpenCIFS.Protocol;

    /// <summary>
    /// Maintains the SMB 3.1.1 preauthentication integrity transcript hash.
    /// </summary>
    public sealed class PreauthIntegrityHashAccumulator
    {
        /// <summary>
        /// Initialize the accumulator.
        /// </summary>
        /// <param name="algorithmId">Hash algorithm identifier.</param>
        public PreauthIntegrityHashAccumulator(HashAlgorithmId algorithmId = HashAlgorithmId.Sha512)
        {
            AlgorithmId = algorithmId;
            _CurrentHash = CreateInitialHash(algorithmId);
        }

        /// <summary>
        /// Negotiated hash algorithm.
        /// </summary>
        public HashAlgorithmId AlgorithmId { get; }

        /// <summary>
        /// Current transcript hash value.
        /// </summary>
        public byte[] CurrentHash
        {
            get
            {
                byte[] value = new byte[_CurrentHash.Length];
                Array.Copy(_CurrentHash, value, _CurrentHash.Length);
                return value;
            }
        }

        /// <summary>
        /// Append a message to the transcript hash.
        /// </summary>
        /// <param name="message">Message bytes.</param>
        public void Append(ReadOnlySpan<byte> message)
        {
            byte[] input = new byte[_CurrentHash.Length + message.Length];
            Buffer.BlockCopy(_CurrentHash, 0, input, 0, _CurrentHash.Length);
            message.CopyTo(input.AsSpan(_CurrentHash.Length));
            _CurrentHash = ComputeHash(input, AlgorithmId);
        }

        /// <summary>
        /// Reset the accumulator to its initial zero transcript state.
        /// </summary>
        public void Reset()
        {
            _CurrentHash = CreateInitialHash(AlgorithmId);
        }

        private static byte[] ComputeHash(byte[] input, HashAlgorithmId algorithmId)
        {
            if (algorithmId != HashAlgorithmId.Sha512)
            {
                throw new NotSupportedException("Only SHA-512 preauthentication hashing is currently supported.");
            }

            return SHA512.HashData(input);
        }

        private static byte[] CreateInitialHash(HashAlgorithmId algorithmId)
        {
            if (algorithmId != HashAlgorithmId.Sha512)
            {
                throw new NotSupportedException("Only SHA-512 preauthentication hashing is currently supported.");
            }

            return new byte[64];
        }

        private byte[] _CurrentHash;
    }
}

