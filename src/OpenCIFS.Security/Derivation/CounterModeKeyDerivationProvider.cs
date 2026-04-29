namespace OpenCIFS.Security
{
    using System.Buffers.Binary;
    using System.Security.Cryptography;

    /// <summary>
    /// Derives SMB 3.x subkeys with SP800-108 counter-mode HMAC-SHA256.
    /// </summary>
    public sealed class CounterModeKeyDerivationProvider : IKeyDerivationProvider
    {
        private const int HashLength = 32;

        /// <inheritdoc />
        public byte[] DeriveKey(ReadOnlySpan<byte> sessionSecret, ReadOnlySpan<byte> label, ReadOnlySpan<byte> context, int outputLength)
        {
            if (sessionSecret.IsEmpty)
            {
                throw new ArgumentException("Session secret must not be empty.", nameof(sessionSecret));
            }

            if (outputLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be greater than zero.");
            }

            int iterationCount = (outputLength + HashLength - 1) / HashLength;
            byte[] derivedMaterial = new byte[iterationCount * HashLength];

            for (int iteration = 1; iteration <= iterationCount; iteration++)
            {
                byte[] input = new byte[4 + label.Length + 1 + context.Length + 4];
                BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(0, 4), (uint)iteration);
                label.CopyTo(input.AsSpan(4, label.Length));
                input[4 + label.Length] = 0x00;
                context.CopyTo(input.AsSpan(5 + label.Length, context.Length));
                BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(input.Length - 4), checked((uint)outputLength * 8U));

                using HMACSHA256 algorithm = new HMACSHA256(sessionSecret.ToArray());
                byte[] block = algorithm.ComputeHash(input);
                Buffer.BlockCopy(block, 0, derivedMaterial, (iteration - 1) * HashLength, HashLength);
            }

            byte[] result = new byte[outputLength];
            Buffer.BlockCopy(derivedMaterial, 0, result, 0, outputLength);
            return result;
        }
    }
}
