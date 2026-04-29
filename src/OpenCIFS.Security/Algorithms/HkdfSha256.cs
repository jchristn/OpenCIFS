namespace OpenCIFS.Security
{
    using System.Security.Cryptography;

    /// <summary>
    /// Computes RFC 5869 HKDF values with SHA-256.
    /// </summary>
    public static class HkdfSha256
    {
        private const int HashLength = 32;

        /// <summary>
        /// Perform the HKDF-Extract step with SHA-256.
        /// </summary>
        /// <param name="inputKeyMaterial">Input key material.</param>
        /// <param name="salt">Optional salt bytes.</param>
        /// <returns>Pseudorandom key bytes.</returns>
        public static byte[] Extract(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt)
        {
#if NET10_0_OR_GREATER
            return HKDF.Extract(HashAlgorithmName.SHA256, inputKeyMaterial.ToArray(), salt.ToArray());
#else
            byte[] effectiveSalt;

            if (salt.Length == 0)
            {
                effectiveSalt = new byte[HashLength];
            }
            else
            {
                effectiveSalt = salt.ToArray();
            }

            using HMACSHA256 algorithm = new HMACSHA256(effectiveSalt);
            return algorithm.ComputeHash(inputKeyMaterial.ToArray());
#endif
        }

        /// <summary>
        /// Perform the HKDF-Expand step with SHA-256.
        /// </summary>
        /// <param name="pseudorandomKey">Pseudorandom key bytes.</param>
        /// <param name="info">Application-specific context bytes.</param>
        /// <param name="outputLength">Desired output length in bytes.</param>
        /// <returns>Expanded key bytes.</returns>
        public static byte[] Expand(ReadOnlySpan<byte> pseudorandomKey, ReadOnlySpan<byte> info, int outputLength)
        {
            if (outputLength <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length must be greater than zero.");
            }

            if (outputLength > 255 * HashLength)
            {
                throw new ArgumentOutOfRangeException(nameof(outputLength), "Output length exceeds the RFC 5869 SHA-256 limit.");
            }

#if NET10_0_OR_GREATER
            return HKDF.Expand(HashAlgorithmName.SHA256, pseudorandomKey.ToArray(), outputLength, info.ToArray());
#else
            using HMACSHA256 algorithm = new HMACSHA256(pseudorandomKey.ToArray());
            byte[] output = new byte[outputLength];
            byte[] previousBlock = Array.Empty<byte>();
            int bytesWritten = 0;

            for (byte counter = 1; bytesWritten < outputLength; counter++)
            {
                byte[] input = new byte[previousBlock.Length + info.Length + 1];
                Buffer.BlockCopy(previousBlock, 0, input, 0, previousBlock.Length);
                info.CopyTo(input.AsSpan(previousBlock.Length, info.Length));
                input[input.Length - 1] = counter;
                previousBlock = algorithm.ComputeHash(input);
                int bytesToCopy = Math.Min(previousBlock.Length, outputLength - bytesWritten);
                Buffer.BlockCopy(previousBlock, 0, output, bytesWritten, bytesToCopy);
                bytesWritten += bytesToCopy;
            }

            return output;
#endif
        }

        /// <summary>
        /// Perform the HKDF-Extract and HKDF-Expand steps with SHA-256.
        /// </summary>
        /// <param name="inputKeyMaterial">Input key material.</param>
        /// <param name="salt">Optional salt bytes.</param>
        /// <param name="info">Application-specific context bytes.</param>
        /// <param name="outputLength">Desired output length in bytes.</param>
        /// <returns>Derived key bytes.</returns>
        public static byte[] DeriveKey(ReadOnlySpan<byte> inputKeyMaterial, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> info, int outputLength)
        {
#if NET10_0_OR_GREATER
            return HKDF.DeriveKey(HashAlgorithmName.SHA256, inputKeyMaterial.ToArray(), outputLength, salt.ToArray(), info.ToArray());
#else
            byte[] pseudorandomKey = Extract(inputKeyMaterial, salt);

            try
            {
                return Expand(pseudorandomKey, info, outputLength);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(pseudorandomKey);
            }
#endif
        }
    }
}
